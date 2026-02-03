#!/usr/bin/env python3
# boxctl:
#   category: baremetal/kernel
#   tags: [sysrq, kernel, emergency, recovery, security]
#   requires: []
#   privilege: none
#   related: [kernel_cmdline_audit, sysctl_security_audit]
#   brief: Monitor Magic SysRq key configuration

"""
Monitor Magic SysRq key configuration for baremetal systems.

The Magic SysRq key provides emergency system control capabilities that work
even when the system is otherwise unresponsive. This is critical for large-scale
baremetal environments where physical access may be limited or impossible.

This script monitors:
- Whether SysRq is enabled and at what level
- Which SysRq functions are available
- Security implications of current configuration
- Fleet consistency (comparing against expected baseline)

SysRq bitmask values:
  0 - Disable sysrq completely
  1 - Enable all functions
  >1 - Bitmask enabling specific functions:
    2   - Enable control of console logging level
    4   - Enable control of keyboard (SAK, unraw)
    8   - Enable debugging dumps
    16  - Enable sync command
    32  - Enable remount read-only
    64  - Enable signaling of processes (term, kill, oom-kill)
    128 - Enable reboot/poweroff
    256 - Enable nicing of RT tasks
"""

import argparse
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


SYSRQ_PATH = '/proc/sys/kernel/sysrq'

# SysRq bitmask definitions
SYSRQ_FUNCTIONS = {
    2: {
        'name': 'loglevel',
        'description': 'Control console logging level (0-9)',
        'severity': 'low',
        'keys': ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9'],
    },
    4: {
        'name': 'keyboard',
        'description': 'Keyboard control (SAK, unraw)',
        'severity': 'medium',
        'keys': ['k', 'r'],
    },
    8: {
        'name': 'debug',
        'description': 'Debugging dumps (memory, registers, tasks)',
        'severity': 'low',
        'keys': ['d', 'l', 'm', 'p', 'q', 't', 'w', 'x', 'z'],
    },
    16: {
        'name': 'sync',
        'description': 'Sync filesystems',
        'severity': 'low',
        'keys': ['s'],
    },
    32: {
        'name': 'remount_ro',
        'description': 'Remount filesystems read-only',
        'severity': 'low',
        'keys': ['u'],
    },
    64: {
        'name': 'signal',
        'description': 'Process signaling (SIGTERM, SIGKILL, OOM kill)',
        'severity': 'high',
        'keys': ['e', 'f', 'i'],
    },
    128: {
        'name': 'reboot',
        'description': 'Reboot/poweroff system',
        'severity': 'high',
        'keys': ['b', 'c', 'o'],
    },
    256: {
        'name': 'nice',
        'description': 'Nice RT tasks',
        'severity': 'low',
        'keys': ['n'],
    },
}

COMMON_CONFIGS = {
    0: 'Completely disabled (most restrictive)',
    1: 'All functions enabled (least restrictive)',
    176: 'Sync + remount-ro + reboot only (Ubuntu/Debian default)',
    438: 'All except debugging and keyboard (common secure config)',
    502: 'All except keyboard control',
}


def decode_sysrq_value(value: int) -> dict[str, Any]:
    """Decode SysRq bitmask into enabled functions."""
    if value == 0:
        return {
            'enabled': False,
            'all_enabled': False,
            'functions': [],
            'available_keys': [],
        }

    if value == 1:
        # Value 1 enables all functions
        functions = []
        all_keys = []
        for bit, info in SYSRQ_FUNCTIONS.items():
            functions.append({
                'bit': bit,
                'name': info['name'],
                'description': info['description'],
                'severity': info['severity'],
                'keys': info['keys'],
            })
            all_keys.extend(info['keys'])

        return {
            'enabled': True,
            'all_enabled': True,
            'functions': functions,
            'available_keys': sorted(set(all_keys)),
        }

    # Decode bitmask
    functions = []
    all_keys = []
    for bit, info in SYSRQ_FUNCTIONS.items():
        if value & bit:
            functions.append({
                'bit': bit,
                'name': info['name'],
                'description': info['description'],
                'severity': info['severity'],
                'keys': info['keys'],
            })
            all_keys.extend(info['keys'])

    return {
        'enabled': len(functions) > 0,
        'all_enabled': False,
        'functions': functions,
        'available_keys': sorted(set(all_keys)),
    }


def analyze_security(decoded: dict[str, Any]) -> tuple[list[str], list[str]]:
    """Analyze security implications of current configuration."""
    issues = []
    warnings = []

    if not decoded['enabled']:
        warnings.append("SysRq completely disabled - emergency recovery impossible")
        return issues, warnings

    if decoded['all_enabled']:
        warnings.append("All SysRq functions enabled - consider restricting for security")

    # Check for high-severity functions
    for func in decoded['functions']:
        if func['severity'] == 'high':
            if func['name'] == 'signal':
                warnings.append(
                    f"Process signaling enabled (keys: {', '.join(func['keys'])}) - "
                    "allows killing all processes"
                )
            elif func['name'] == 'reboot':
                warnings.append(
                    f"Reboot/crash/poweroff enabled (keys: {', '.join(func['keys'])}) - "
                    "allows immediate system shutdown"
                )

    # Check for recommended emergency functions
    has_sync = any(f['name'] == 'sync' for f in decoded['functions'])
    has_remount = any(f['name'] == 'remount_ro' for f in decoded['functions'])
    has_reboot = any(f['name'] == 'reboot' for f in decoded['functions'])

    if not has_sync:
        issues.append("Sync function disabled - cannot safely flush data before crash")
    if not has_remount:
        issues.append("Remount-ro disabled - cannot protect filesystems before crash")
    if not has_reboot:
        warnings.append("Reboot disabled - may need physical access for recovery")

    return issues, warnings


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
        description="Monitor Magic SysRq key configuration"
    )
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show detailed function information")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    parser.add_argument("--expected", type=int, metavar="VALUE",
                        help="Expected SysRq value (0-511). Alert if current value differs.")
    parser.add_argument("--require-emergency", action="store_true",
                        help="Require sync, remount-ro, and reboot functions")
    opts = parser.parse_args(args)

    # Validate expected value
    if opts.expected is not None and (opts.expected < 0 or opts.expected > 511):
        output.error("Expected value must be between 0 and 511")

        output.render(opts.format, "Monitor Magic SysRq key configuration")
        return 2

    # Read SysRq value
    try:
        sysrq_content = context.read_file(SYSRQ_PATH)
        sysrq_value = int(sysrq_content.strip())
    except FileNotFoundError:
        output.error("/proc/sys/kernel/sysrq not found - SysRq may not be compiled into kernel")

        output.render(opts.format, "Monitor Magic SysRq key configuration")
        return 2
    except ValueError:
        output.error("Unable to parse SysRq value")

        output.render(opts.format, "Monitor Magic SysRq key configuration")
        return 2
    except PermissionError:
        output.error("Permission denied reading /proc/sys/kernel/sysrq")

        output.render(opts.format, "Monitor Magic SysRq key configuration")
        return 2

    # Decode and analyze
    decoded = decode_sysrq_value(sysrq_value)
    issues, warnings = analyze_security(decoded)

    # Check expected value
    matches_expected = opts.expected is None or sysrq_value == opts.expected

    # Check emergency requirements if requested
    if opts.require_emergency:
        required = ['sync', 'remount_ro', 'reboot']
        enabled_names = [f['name'] for f in decoded['functions']]
        missing = [r for r in required if r not in enabled_names]
        if missing:
            issues.append(f"Emergency functions missing: {', '.join(missing)}")

    # Build result
    config_desc = COMMON_CONFIGS.get(sysrq_value, 'Custom configuration')

    result = {
        'sysrq_value': sysrq_value,
        'config_description': config_desc,
        'enabled': decoded['enabled'],
        'all_enabled': decoded['all_enabled'],
        'functions': decoded['functions'],
        'available_keys': decoded['available_keys'],
        'summary': {
            'total_functions': len(decoded['functions']),
            'high_severity': sum(1 for f in decoded['functions'] if f['severity'] == 'high'),
            'medium_severity': sum(1 for f in decoded['functions'] if f['severity'] == 'medium'),
            'low_severity': sum(1 for f in decoded['functions'] if f['severity'] == 'low'),
        },
        'security': {
            'issues': issues,
            'warnings': warnings,
        },
        'expected_value': opts.expected,
        'matches_expected': matches_expected,
    }

    output.emit(result)

    # Set summary
    if not matches_expected:
        output.set_summary(f"SysRq value mismatch: expected {opts.expected}, got {sysrq_value}")
    elif issues:
        output.set_summary(f"SysRq {sysrq_value}: {len(issues)} issues")
    elif warnings:
        output.set_summary(f"SysRq {sysrq_value}: {len(warnings)} warnings")
    else:
        output.set_summary(f"SysRq {sysrq_value}: {config_desc}")

    # Determine exit code
    has_issues = issues or not matches_expected
    has_warnings = bool(warnings)

    if has_issues or has_warnings:

        output.render(opts.format, "Monitor Magic SysRq key configuration")
        return 1
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
