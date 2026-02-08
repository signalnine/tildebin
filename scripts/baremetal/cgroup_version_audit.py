#!/usr/bin/env python3
# boxctl:
#   category: baremetal/kernel
#   tags: [kernel, cgroup, v1, v2, migration, containers]
#   requires: []
#   privilege: user
#   related: [cgroup_cpu_limits, cgroup_memory_limits, cgroup_pressure, container_runtime_health]
#   brief: Audit cgroup v1 vs v2 configuration and detect hybrid mode

"""
Audit cgroup v1 vs v2 configuration and detect hybrid mode.

Detects whether the system uses cgroup v1 (legacy), cgroup v2 (unified),
or a hybrid of both. Hybrid mode can cause confusion with container runtimes
and is generally discouraged. Reports which controllers are on which version.

Reads from:
- /proc/mounts for cgroup2 filesystem presence
- /proc/cgroups for v1 controller hierarchies
- /sys/fs/cgroup/cgroup.controllers for v2 available controllers

Exit codes:
    0 - Clean cgroup configuration (pure v1 or pure v2)
    1 - Hybrid mode detected
    2 - Error or missing dependencies
"""

import argparse
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def parse_proc_mounts(content: str) -> bool:
    """Check if cgroup2 filesystem is mounted.

    Returns True if cgroup2 is found in /proc/mounts.
    """
    for line in content.split('\n'):
        parts = line.strip().split()
        if len(parts) >= 3 and parts[2] == 'cgroup2':
            return True
    return False


def parse_proc_cgroups(content: str) -> list[dict[str, Any]]:
    """Parse /proc/cgroups for v1 controller info.

    Format: subsys_name hierarchy num_cgroups enabled
    Controllers with hierarchy > 0 are on a v1 hierarchy.

    Returns list of controller dicts.
    """
    controllers = []
    for line in content.split('\n'):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split()
        if len(parts) >= 4:
            try:
                controllers.append({
                    'name': parts[0],
                    'hierarchy': int(parts[1]),
                    'num_cgroups': int(parts[2]),
                    'enabled': int(parts[3]) == 1,
                })
            except (ValueError, IndexError):
                continue
    return controllers


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = clean config, 1 = hybrid detected, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Audit cgroup v1 vs v2 configuration and detect hybrid mode"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Show controller details")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    opts = parser.parse_args(args)

    # Check /proc/cgroups exists
    if not context.file_exists('/proc/cgroups'):
        output.error("/proc/cgroups not found")
        output.render(opts.format, "cgroup Version Audit")
        return 2

    # Read /proc/mounts for cgroup2
    v2_mounted = False
    try:
        mounts = context.read_file('/proc/mounts')
        v2_mounted = parse_proc_mounts(mounts)
    except FileNotFoundError:
        pass

    # Read /proc/cgroups for v1 controllers
    try:
        cgroups_content = context.read_file('/proc/cgroups')
    except Exception as e:
        output.error(f"Error reading /proc/cgroups: {e}")
        output.render(opts.format, "cgroup Version Audit")
        return 2

    all_controllers = parse_proc_cgroups(cgroups_content)
    v1_active = [c for c in all_controllers if c['hierarchy'] > 0 and c['enabled']]
    v1_controller_names = [c['name'] for c in v1_active]

    # Read v2 controllers
    v2_controllers: list[str] = []
    try:
        v2_content = context.read_file('/sys/fs/cgroup/cgroup.controllers')
        v2_controllers = v2_content.strip().split()
    except FileNotFoundError:
        pass

    # Determine mode
    issues: list[dict[str, Any]] = []

    if v2_mounted and v1_active:
        mode = 'hybrid'
        issues.append({
            'severity': 'WARNING',
            'type': 'hybrid_mode',
            'v1_controllers': v1_controller_names,
            'v2_controllers': v2_controllers,
            'message': (
                f"Hybrid cgroup mode: v2 mounted with {len(v1_active)} v1 "
                f"controllers still active ({', '.join(v1_controller_names)})"
            ),
        })
    elif v2_mounted and not v1_active:
        mode = 'v2'
    elif not v2_mounted and v1_active:
        mode = 'v1'
        issues.append({
            'severity': 'INFO',
            'type': 'v1_only',
            'v1_controllers': v1_controller_names,
            'message': (
                f"cgroup v1 only ({len(v1_active)} controllers). "
                f"Consider migrating to cgroup v2 (unified hierarchy)"
            ),
        })
    else:
        mode = 'unknown'

    # Emit data
    data: dict[str, Any] = {
        'mode': mode,
        'v2_mounted': v2_mounted,
        'v1_controllers': v1_controller_names,
        'v2_controllers': v2_controllers,
        'issues': issues,
    }

    if opts.verbose:
        data['all_controllers'] = all_controllers

    output.emit(data)

    # Summary
    output.set_summary(f"mode={mode}, v1={len(v1_active)}, v2={len(v2_controllers)}")
    output.render(opts.format, "cgroup Version Audit")

    has_issues = any(i['severity'] in ('CRITICAL', 'WARNING') for i in issues)
    return 1 if has_issues else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
