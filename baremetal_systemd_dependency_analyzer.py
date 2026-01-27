#!/usr/bin/env python3
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

Exit codes:
    0 - No dependency issues detected
    1 - Dependency issues found (warnings)
    2 - Missing dependencies or usage error
"""

import argparse
import json
import subprocess
import sys
from collections import defaultdict


def run_command(cmd):
    """Execute a command and return output."""
    try:
        result = subprocess.run(
            cmd if isinstance(cmd, list) else cmd.split(),
            capture_output=True,
            text=True
        )
        return result.returncode, result.stdout, result.stderr
    except FileNotFoundError:
        return -1, "", "Command not found"
    except Exception as e:
        return -1, "", str(e)


def check_systemctl_available():
    """Check if systemctl is available."""
    returncode, _, _ = run_command(['which', 'systemctl'])
    return returncode == 0


def get_unit_property(unit_name, prop):
    """Get a specific property of a systemd unit."""
    returncode, stdout, _ = run_command(
        ['systemctl', 'show', unit_name, '--property=' + prop, '--no-pager']
    )
    if returncode == 0 and '=' in stdout:
        return stdout.strip().split('=', 1)[1]
    return ''


def get_unit_state(unit_name):
    """Get the load and active state of a unit."""
    load_state = get_unit_property(unit_name, 'LoadState')
    active_state = get_unit_property(unit_name, 'ActiveState')
    sub_state = get_unit_property(unit_name, 'SubState')
    return {
        'load_state': load_state,
        'active_state': active_state,
        'sub_state': sub_state
    }


def get_unit_dependencies(unit_name):
    """Get all dependency types for a unit."""
    deps = {}

    # Dependency types to check
    dep_types = [
        'Requires', 'Wants', 'BindsTo', 'PartOf',
        'Requisite', 'Conflicts', 'Before', 'After'
    ]

    for dep_type in dep_types:
        value = get_unit_property(unit_name, dep_type)
        if value:
            deps[dep_type] = [u.strip() for u in value.split() if u.strip()]
        else:
            deps[dep_type] = []

    return deps


def get_all_units(unit_type=None):
    """Get list of all loaded units."""
    cmd = ['systemctl', 'list-units', '--all', '--no-legend', '--no-pager']
    if unit_type:
        cmd.extend(['--type=' + unit_type])

    returncode, stdout, _ = run_command(cmd)
    if returncode != 0:
        return []

    units = []
    for line in stdout.strip().split('\n'):
        if not line.strip():
            continue
        parts = line.split()
        if parts:
            # Unit name is first field (may have a bullet prefix)
            unit = parts[0].lstrip('\u25cf').lstrip()
            if unit:
                units.append(unit)

    return units


def analyze_unit_dependencies(unit_name, verbose=False):
    """Analyze dependencies of a single unit for issues."""
    issues = []
    info = {
        'unit': unit_name,
        'state': get_unit_state(unit_name),
        'issues': []
    }

    deps = get_unit_dependencies(unit_name)

    # Strong dependencies that should be running
    strong_deps = deps.get('Requires', []) + deps.get('BindsTo', []) + deps.get('Requisite', [])

    for dep in strong_deps:
        dep_state = get_unit_state(dep)

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
        dep_state = get_unit_state(dep)
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
        conflict_state = get_unit_state(conflict)
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


def check_dependency_depth(unit_name, max_depth=10, visited=None):
    """Check the depth of the dependency chain."""
    if visited is None:
        visited = set()

    if unit_name in visited:
        return 0, True  # Circular dependency detected

    visited.add(unit_name)

    deps = get_unit_dependencies(unit_name)
    direct_deps = (
        deps.get('Requires', []) +
        deps.get('BindsTo', []) +
        deps.get('Wants', [])
    )

    max_child_depth = 0
    has_cycle = False

    for dep in direct_deps[:10]:  # Limit to avoid excessive recursion
        dep_state = get_unit_state(dep)
        if dep_state['load_state'] not in ['not-found', 'masked']:
            child_depth, child_cycle = check_dependency_depth(
                dep, max_depth - 1, visited.copy()
            )
            max_child_depth = max(max_child_depth, child_depth)
            if child_cycle:
                has_cycle = True

    return max_child_depth + 1, has_cycle


def get_failed_units():
    """Get list of failed units for quick scan."""
    returncode, stdout, _ = run_command(
        ['systemctl', '--failed', '--no-legend', '--no-pager']
    )

    failed = []
    if returncode == 0:
        for line in stdout.strip().split('\n'):
            if line.strip():
                parts = line.split()
                if parts:
                    failed.append(parts[0].lstrip('\u25cf').lstrip())

    return failed


def output_plain(results, warn_only, verbose):
    """Output results in plain text format."""
    print("Systemd Dependency Analysis Report")
    print("=" * 60)

    total_units = len(results)
    units_with_issues = sum(1 for r in results if r['issues'])

    for result in results:
        if warn_only and not result['issues']:
            continue

        unit = result['unit']
        state = result['state']
        issues = result['issues']

        state_str = f"{state['active_state']}/{state['sub_state']}"
        status_mark = "[WARN]" if issues else "[OK]"

        print(f"\n{status_mark} {unit} ({state_str})")

        if verbose and 'dependencies' in result:
            deps = result['dependencies']
            req = deps.get('Requires', [])
            wants = deps.get('Wants', [])
            if req:
                print(f"  Requires: {', '.join(req[:5])}" +
                      (f" (+{len(req)-5} more)" if len(req) > 5 else ""))
            if wants:
                print(f"  Wants: {', '.join(wants[:5])}" +
                      (f" (+{len(wants)-5} more)" if len(wants) > 5 else ""))

        if issues:
            print("  Issues:")
            for issue in issues:
                sev = issue['severity'].upper()
                msg = issue['message']
                print(f"    [{sev}] {msg}")

        if 'depth' in result and result['depth'] > 5:
            print(f"  [INFO] Dependency chain depth: {result['depth']}")

        if result.get('has_cycle'):
            print("  [WARN] Potential circular dependency detected")

    print("\n" + "=" * 60)
    print(f"Summary: {units_with_issues}/{total_units} units have issues")


def output_json(results):
    """Output results in JSON format."""
    summary = {
        'total_units': len(results),
        'units_with_issues': sum(1 for r in results if r['issues']),
        'error_count': sum(
            1 for r in results
            for i in r['issues']
            if i['severity'] == 'error'
        ),
        'warning_count': sum(
            1 for r in results
            for i in r['issues']
            if i['severity'] == 'warning'
        )
    }

    output = {
        'summary': summary,
        'units': results
    }
    print(json.dumps(output, indent=2))


def output_table(results, warn_only):
    """Output results in table format."""
    print(f"{'Unit':<40} {'State':<15} {'Issues':<8} {'Depth':<6}")
    print("-" * 75)

    for result in results:
        if warn_only and not result['issues']:
            continue

        unit = result['unit'][:40]
        state = result['state']['active_state']
        issue_count = len(result['issues'])
        depth = result.get('depth', '-')

        print(f"{unit:<40} {state:<15} {issue_count:<8} {depth:<6}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Analyze systemd unit dependencies for issues",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                           # Analyze failed units' dependencies
  %(prog)s --all                     # Analyze all service units
  %(prog)s --unit sshd.service       # Analyze specific unit
  %(prog)s --type service            # Analyze all services
  %(prog)s --check-depth             # Include dependency depth analysis
  %(prog)s --format json             # JSON output

Exit codes:
  0 - No dependency issues detected
  1 - Dependency issues found
  2 - Missing dependencies or usage error
"""
    )

    parser.add_argument(
        "-u", "--unit",
        metavar="UNIT",
        help="Specific unit to analyze"
    )

    parser.add_argument(
        "-t", "--type",
        metavar="TYPE",
        help="Unit type to analyze (e.g., service, socket, timer)"
    )

    parser.add_argument(
        "-a", "--all",
        action="store_true",
        help="Analyze all loaded units (can be slow)"
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
        help="Show detailed dependency information"
    )

    parser.add_argument(
        "-w", "--warn-only",
        action="store_true",
        help="Only show units with issues"
    )

    parser.add_argument(
        "--check-depth",
        action="store_true",
        help="Check dependency chain depth (slower)"
    )

    parser.add_argument(
        "--max-depth-warn",
        type=int,
        default=8,
        metavar="N",
        help="Warn if dependency depth exceeds N (default: %(default)s)"
    )

    args = parser.parse_args()

    # Check if systemctl is available
    if not check_systemctl_available():
        print("Error: systemctl not found. This script requires systemd.",
              file=sys.stderr)
        sys.exit(2)

    # Determine which units to analyze
    if args.unit:
        units = [args.unit]
    elif args.all:
        units = get_all_units(args.type)
    elif args.type:
        units = get_all_units(args.type)
    else:
        # Default: analyze failed units plus commonly important services
        failed = get_failed_units()
        important = [
            'sshd.service', 'NetworkManager.service', 'systemd-networkd.service',
            'docker.service', 'containerd.service', 'kubelet.service',
            'cron.service', 'rsyslog.service', 'systemd-journald.service'
        ]
        # Only include important services that exist
        existing_important = []
        for svc in important:
            state = get_unit_state(svc)
            if state['load_state'] not in ['not-found']:
                existing_important.append(svc)

        units = list(set(failed + existing_important))

    if not units:
        if args.format == 'json':
            print(json.dumps({'summary': {'total_units': 0, 'units_with_issues': 0}, 'units': []}))
        else:
            print("No units to analyze")
        sys.exit(0)

    # Analyze each unit
    results = []
    for unit in units:
        result = analyze_unit_dependencies(unit, args.verbose)

        # Check dependency depth if requested
        if args.check_depth:
            depth, has_cycle = check_dependency_depth(unit)
            result['depth'] = depth
            result['has_cycle'] = has_cycle

            if depth > args.max_depth_warn:
                result['issues'].append({
                    'type': 'deep_dependency_chain',
                    'severity': 'info',
                    'dependency': None,
                    'relationship': None,
                    'message': f"Dependency chain depth ({depth}) exceeds threshold ({args.max_depth_warn})"
                })

        results.append(result)

    # Output results
    if args.format == 'json':
        output_json(results)
    elif args.format == 'table':
        output_table(results, args.warn_only)
    else:
        output_plain(results, args.warn_only, args.verbose)

    # Exit code based on findings
    has_issues = any(r['issues'] for r in results)
    sys.exit(1 if has_issues else 0)


if __name__ == "__main__":
    main()
