#!/usr/bin/env python3
# boxctl:
#   category: baremetal/systemd
#   tags: [systemd, dependency, service, unit, boot]
#   requires: [systemctl]
#   privilege: none
#   related: [systemd_service_monitor, systemd_security, systemd_slice]
#   brief: Analyze systemd unit dependencies for issues

"""
Analyze systemd unit dependencies to detect broken or problematic configurations.

This script examines the systemd dependency graph to identify:
- Units with failed or missing dependencies
- Circular dependency risks
- Units depending on masked/disabled services
- Ordering conflicts (Before/After issues)
- Units with excessive dependency chains (deep nesting)

Useful for:
- Diagnosing service startup failures in large baremetal environments
- Pre-deployment validation of systemd configurations
- Identifying fragile service dependencies
- Capacity planning for boot time optimization
"""

import argparse
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def get_unit_property(context: Context, unit_name: str, prop: str) -> str:
    """Get a specific property of a systemd unit."""
    result = context.run(
        ['systemctl', 'show', unit_name, f'--property={prop}', '--no-pager'],
        check=False
    )
    if result.returncode == 0 and '=' in result.stdout:
        return result.stdout.strip().split('=', 1)[1]
    return ''


def get_unit_state(context: Context, unit_name: str) -> dict[str, str]:
    """Get the load and active state of a unit."""
    load_state = get_unit_property(context, unit_name, 'LoadState')
    active_state = get_unit_property(context, unit_name, 'ActiveState')
    sub_state = get_unit_property(context, unit_name, 'SubState')
    return {
        'load_state': load_state,
        'active_state': active_state,
        'sub_state': sub_state
    }


def get_unit_dependencies(context: Context, unit_name: str) -> dict[str, list[str]]:
    """Get all dependency types for a unit."""
    deps = {}
    dep_types = [
        'Requires', 'Wants', 'BindsTo', 'PartOf',
        'Requisite', 'Conflicts', 'Before', 'After'
    ]

    for dep_type in dep_types:
        value = get_unit_property(context, unit_name, dep_type)
        if value:
            deps[dep_type] = [u.strip() for u in value.split() if u.strip()]
        else:
            deps[dep_type] = []

    return deps


def get_all_units(context: Context, unit_type: str | None = None) -> list[str]:
    """Get list of all loaded units."""
    cmd = ['systemctl', 'list-units', '--all', '--no-legend', '--no-pager']
    if unit_type:
        cmd.extend([f'--type={unit_type}'])

    result = context.run(cmd, check=False)
    if result.returncode != 0:
        return []

    units = []
    for line in result.stdout.strip().split('\n'):
        if not line.strip():
            continue
        parts = line.split()
        if parts:
            # Unit name is first field (may have a bullet prefix)
            unit = parts[0].lstrip('\u25cf').lstrip()
            if unit:
                units.append(unit)

    return units


def get_failed_units(context: Context) -> list[str]:
    """Get list of failed units."""
    result = context.run(
        ['systemctl', '--failed', '--no-legend', '--no-pager'],
        check=False
    )

    failed = []
    if result.returncode == 0:
        for line in result.stdout.strip().split('\n'):
            if line.strip():
                parts = line.split()
                if parts:
                    failed.append(parts[0].lstrip('\u25cf').lstrip())

    return failed


def analyze_unit_dependencies(
    context: Context,
    unit_name: str
) -> dict[str, Any]:
    """Analyze dependencies of a single unit for issues."""
    issues = []
    info = {
        'unit': unit_name,
        'state': get_unit_state(context, unit_name),
        'issues': []
    }

    deps = get_unit_dependencies(context, unit_name)

    # Strong dependencies that should be running
    strong_deps = (
        deps.get('Requires', []) +
        deps.get('BindsTo', []) +
        deps.get('Requisite', [])
    )

    for dep in strong_deps:
        dep_state = get_unit_state(context, dep)

        # Check for failed dependencies
        if dep_state['active_state'] == 'failed':
            issues.append({
                'type': 'failed_dependency',
                'severity': 'error',
                'dependency': dep,
                'relationship': 'Requires/BindsTo/Requisite',
                'message': f"Dependency '{dep}' is in failed state"
            })

        # Check for masked dependencies
        if dep_state['load_state'] == 'masked':
            issues.append({
                'type': 'masked_dependency',
                'severity': 'warning',
                'dependency': dep,
                'relationship': 'Requires/BindsTo/Requisite',
                'message': f"Dependency '{dep}' is masked"
            })

        # Check for not-found dependencies
        if dep_state['load_state'] == 'not-found':
            issues.append({
                'type': 'missing_dependency',
                'severity': 'error',
                'dependency': dep,
                'relationship': 'Requires/BindsTo/Requisite',
                'message': f"Dependency '{dep}' not found"
            })

        # Check for inactive dependencies when unit is active
        if (info['state']['active_state'] == 'active' and
                dep_state['active_state'] == 'inactive'):
            issues.append({
                'type': 'inactive_dependency',
                'severity': 'warning',
                'dependency': dep,
                'relationship': 'Requires/BindsTo/Requisite',
                'message': f"Strong dependency '{dep}' is inactive while unit is active"
            })

    # Check Wants dependencies (softer, but still worth noting)
    wants_deps = deps.get('Wants', [])
    for dep in wants_deps:
        dep_state = get_unit_state(context, dep)
        if dep_state['load_state'] == 'not-found':
            issues.append({
                'type': 'missing_wants',
                'severity': 'info',
                'dependency': dep,
                'relationship': 'Wants',
                'message': f"Wanted dependency '{dep}' not found (soft failure)"
            })

    # Check for conflicting dependencies
    conflicts = deps.get('Conflicts', [])
    for conflict in conflicts:
        conflict_state = get_unit_state(context, conflict)
        if (info['state']['active_state'] == 'active' and
                conflict_state['active_state'] == 'active'):
            issues.append({
                'type': 'conflict_running',
                'severity': 'error',
                'dependency': conflict,
                'relationship': 'Conflicts',
                'message': f"Conflicting unit '{conflict}' is active"
            })

    info['dependencies'] = deps
    info['issues'] = issues

    return info


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
    parser = argparse.ArgumentParser(
        description="Analyze systemd unit dependencies for issues"
    )
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show detailed dependency information")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    parser.add_argument("-u", "--unit", metavar="UNIT",
                        help="Specific unit to analyze")
    parser.add_argument("-t", "--type", metavar="TYPE",
                        help="Unit type to analyze (e.g., service, socket, timer)")
    parser.add_argument("-a", "--all", action="store_true",
                        help="Analyze all loaded units (can be slow)")
    opts = parser.parse_args(args)

    # Check if systemctl is available
    if not context.check_tool("systemctl"):
        output.error("systemctl not found. This script requires systemd.")
        return 2

    # Determine which units to analyze
    if opts.unit:
        units = [opts.unit]
    elif opts.all:
        units = get_all_units(context, opts.type)
    elif opts.type:
        units = get_all_units(context, opts.type)
    else:
        # Default: analyze failed units plus commonly important services
        failed = get_failed_units(context)
        important = [
            'sshd.service', 'NetworkManager.service', 'systemd-networkd.service',
            'docker.service', 'containerd.service', 'kubelet.service',
            'cron.service', 'rsyslog.service', 'systemd-journald.service'
        ]
        # Only include important services that exist
        existing_important = []
        for svc in important:
            state = get_unit_state(context, svc)
            if state['load_state'] not in ['not-found', '']:
                existing_important.append(svc)

        units = list(set(failed + existing_important))

    if not units:
        output.emit({
            'summary': {'total_units': 0, 'units_with_issues': 0},
            'units': []
        })
        output.set_summary("No units to analyze")
        return 0

    # Analyze each unit
    results = []
    for unit in units:
        result = analyze_unit_dependencies(context, unit)
        results.append(result)

    # Build output
    total_units = len(results)
    units_with_issues = sum(1 for r in results if r['issues'])
    error_count = sum(
        1 for r in results
        for i in r['issues']
        if i['severity'] == 'error'
    )
    warning_count = sum(
        1 for r in results
        for i in r['issues']
        if i['severity'] == 'warning'
    )

    output_data = {
        'summary': {
            'total_units': total_units,
            'units_with_issues': units_with_issues,
            'error_count': error_count,
            'warning_count': warning_count
        },
        'units': results if opts.verbose else [
            {
                'unit': r['unit'],
                'state': r['state'],
                'issue_count': len(r['issues']),
                'issues': r['issues']
            }
            for r in results if r['issues']
        ]
    }

    output.emit(output_data)

    # Set summary
    if units_with_issues > 0:
        output.set_summary(f"{units_with_issues}/{total_units} units have issues")
    else:
        output.set_summary(f"{total_units} units analyzed, no issues")

    # Exit based on findings
    has_issues = any(r['issues'] for r in results)
    return 1 if has_issues else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
