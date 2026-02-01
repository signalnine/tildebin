#!/usr/bin/env python3
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

SysRq functions:
  b - Reboot immediately (no sync/unmount)
  c - Crash the system (trigger kernel panic for dump)
  d - Show all held locks
  e - SIGTERM to all processes except init
  f - OOM killer invocation
  g - Switch to kernel debugger (kgdb)
  h - Help
  i - SIGKILL to all processes except init
  j - Thaw frozen filesystems
  k - Secure Access Key (SAK) - kill all processes on current VT
  l - Show backtrace for all CPUs
  m - Dump memory info
  n - Reset nice level of RT tasks
  o - Power off immediately
  p - Dump registers/flags
  q - Dump all timer info
  r - Turn off keyboard raw mode
  s - Sync all mounted filesystems
  t - Dump current tasks and states
  u - Remount all filesystems read-only
  v - Dump Voyager SMP info
  w - Dump blocked (uninterruptible) tasks
  x - Dump ftrace buffer
  z - Dump ftrace buffer
  0-9 - Set console log level

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

Exit codes:
    0 - SysRq configuration matches expected state or is at expected level
    1 - SysRq configuration warnings (unexpected state or security concerns)
    2 - Usage error or unable to read SysRq configuration
"""

import argparse
import json
import sys
from datetime import datetime

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

# Common expected configurations
COMMON_CONFIGS = {
    0: 'Completely disabled (most restrictive)',
    1: 'All functions enabled (least restrictive)',
    176: 'Sync + remount-ro + reboot only (Ubuntu/Debian default)',
    438: 'All except debugging and keyboard (common secure config)',
    502: 'All except keyboard control',
}


def read_sysrq_value():
    """Read the current SysRq value from /proc/sys/kernel/sysrq"""
    try:
        with open('/proc/sys/kernel/sysrq', 'r') as f:
            return int(f.read().strip())
    except FileNotFoundError:
        print("Error: /proc/sys/kernel/sysrq not found", file=sys.stderr)
        print("SysRq may not be compiled into this kernel", file=sys.stderr)
        sys.exit(2)
    except ValueError as e:
        print(f"Error: Unable to parse SysRq value: {e}", file=sys.stderr)
        sys.exit(2)
    except PermissionError:
        print("Error: Permission denied reading /proc/sys/kernel/sysrq",
              file=sys.stderr)
        sys.exit(2)
    except IOError as e:
        print(f"Error reading SysRq configuration: {e}", file=sys.stderr)
        sys.exit(2)


def decode_sysrq_value(value):
    """Decode SysRq bitmask into enabled functions"""
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


def analyze_security(decoded):
    """Analyze security implications of current configuration"""
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
                warnings.append(f"Process signaling enabled (keys: {', '.join(func['keys'])}) - "
                               "allows killing all processes")
            elif func['name'] == 'reboot':
                warnings.append(f"Reboot/crash/poweroff enabled (keys: {', '.join(func['keys'])}) - "
                               "allows immediate system shutdown")

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


def collect_data(expected_value=None):
    """Collect SysRq configuration data"""
    sysrq_value = read_sysrq_value()
    decoded = decode_sysrq_value(sysrq_value)
    issues, warnings = analyze_security(decoded)

    # Determine configuration description
    config_desc = COMMON_CONFIGS.get(sysrq_value, 'Custom configuration')

    data = {
        'timestamp': datetime.now().isoformat(),
        'sysrq_value': sysrq_value,
        'config_description': config_desc,
        'enabled': decoded['enabled'],
        'all_enabled': decoded['all_enabled'],
        'functions': decoded['functions'],
        'available_keys': decoded['available_keys'],
        'summary': {
            'total_functions': len(decoded['functions']),
            'high_severity': sum(1 for f in decoded['functions']
                                 if f['severity'] == 'high'),
            'medium_severity': sum(1 for f in decoded['functions']
                                   if f['severity'] == 'medium'),
            'low_severity': sum(1 for f in decoded['functions']
                                if f['severity'] == 'low'),
        },
        'security': {
            'issues': issues,
            'warnings': warnings,
        },
        'expected_value': expected_value,
        'matches_expected': expected_value is None or sysrq_value == expected_value,
    }

    return data


def output_plain(data, verbose=False, warn_only=False):
    """Output in plain text format"""
    has_issues = (data['security']['issues'] or
                  data['security']['warnings'] or
                  not data['matches_expected'])

    if warn_only and not has_issues:
        return

    print("Magic SysRq Key Configuration")
    print("=" * 50)
    print()

    # Status
    if data['sysrq_value'] == 0:
        print("Status: DISABLED (SysRq completely disabled)")
    elif data['sysrq_value'] == 1:
        print("Status: ENABLED (all functions)")
    else:
        print(f"Status: ENABLED (bitmask: {data['sysrq_value']})")

    print(f"Configuration: {data['config_description']}")
    print()

    # Summary
    if data['enabled']:
        print(f"Active functions: {data['summary']['total_functions']}")
        if data['summary']['high_severity'] > 0:
            print(f"  High severity: {data['summary']['high_severity']}")
        if data['summary']['medium_severity'] > 0:
            print(f"  Medium severity: {data['summary']['medium_severity']}")
        if data['summary']['low_severity'] > 0:
            print(f"  Low severity: {data['summary']['low_severity']}")
        print()

        # Available keys
        if data['available_keys']:
            print(f"Available keys: {', '.join(data['available_keys'])}")
            print()

        # Functions detail (if verbose)
        if verbose and data['functions']:
            print("Enabled functions:")
            print("-" * 50)
            for func in data['functions']:
                severity_marker = "[HIGH]" if func['severity'] == 'high' else \
                                  "[MED] " if func['severity'] == 'medium' else \
                                  "[LOW] "
                print(f"  {severity_marker} {func['name']}: {func['description']}")
                print(f"           Keys: {', '.join(func['keys'])}")
            print()

    # Security issues
    if data['security']['issues']:
        print("ISSUES:")
        for issue in data['security']['issues']:
            print(f"  [!] {issue}")
        print()

    if data['security']['warnings']:
        print("WARNINGS:")
        for warning in data['security']['warnings']:
            print(f"  [*] {warning}")
        print()

    # Expected value mismatch
    if data['expected_value'] is not None and not data['matches_expected']:
        print(f"MISMATCH: Expected SysRq value {data['expected_value']}, "
              f"got {data['sysrq_value']}")
        print()

    # Summary
    if not has_issues:
        print("[OK] SysRq configuration acceptable")


def output_json(data):
    """Output in JSON format"""
    print(json.dumps(data, indent=2))


def output_table(data, warn_only=False):
    """Output in table format"""
    has_issues = (data['security']['issues'] or
                  data['security']['warnings'] or
                  not data['matches_expected'])

    if warn_only and not has_issues:
        return

    print(f"{'Function':<15} {'Severity':<10} {'Keys':<20} {'Description':<30}")
    print("=" * 75)

    if not data['enabled']:
        print(f"{'(disabled)':<15} {'N/A':<10} {'none':<20} {'SysRq completely disabled':<30}")
    else:
        for func in data['functions']:
            keys = ', '.join(func['keys'][:5])
            if len(func['keys']) > 5:
                keys += '...'
            desc = func['description'][:30]
            print(f"{func['name']:<15} {func['severity']:<10} {keys:<20} {desc:<30}")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Monitor Magic SysRq key configuration for baremetal systems',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Common SysRq values:
  0   - Disabled completely
  1   - All functions enabled
  176 - Sync + remount-ro + reboot only (Ubuntu/Debian default)
  438 - All except debugging and keyboard
  502 - All except keyboard control

Emergency recovery sequence (if enabled):
  Alt+SysRq+R - unRaw (take keyboard control from X)
  Alt+SysRq+E - tErminate (SIGTERM to all processes)
  Alt+SysRq+I - kIll (SIGKILL to all processes)
  Alt+SysRq+S - Sync (sync all filesystems)
  Alt+SysRq+U - Unmount (remount read-only)
  Alt+SysRq+B - reBoot

Examples:
  %(prog)s                    # Check current SysRq configuration
  %(prog)s --format json      # JSON output for automation
  %(prog)s --expected 176     # Alert if not at expected value
  %(prog)s -v                 # Show detailed function information

Exit codes:
  0 - Configuration acceptable or matches expected
  1 - Security warnings or configuration mismatch
  2 - Error reading SysRq configuration
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
        help='Show detailed function information'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show output if issues or warnings detected'
    )

    parser.add_argument(
        '--expected',
        type=int,
        metavar='VALUE',
        help='Expected SysRq value (0-511). Alert if current value differs.'
    )

    parser.add_argument(
        '--require-emergency',
        action='store_true',
        help='Require sync, remount-ro, and reboot functions for emergency recovery'
    )

    args = parser.parse_args()

    # Validate expected value
    if args.expected is not None and (args.expected < 0 or args.expected > 511):
        print("Error: Expected value must be between 0 and 511", file=sys.stderr)
        sys.exit(2)

    # Collect data
    data = collect_data(expected_value=args.expected)

    # Check emergency requirements if requested
    if args.require_emergency:
        required = ['sync', 'remount_ro', 'reboot']
        enabled_names = [f['name'] for f in data['functions']]
        missing = [r for r in required if r not in enabled_names]
        if missing:
            data['security']['issues'].append(
                f"Emergency functions missing: {', '.join(missing)}"
            )

    # Output
    if args.format == 'json':
        output_json(data)
    elif args.format == 'table':
        output_table(data, warn_only=args.warn_only)
    else:
        output_plain(data, verbose=args.verbose, warn_only=args.warn_only)

    # Determine exit code
    has_issues = (data['security']['issues'] or
                  not data['matches_expected'])
    has_warnings = bool(data['security']['warnings'])

    if has_issues:
        sys.exit(1)
    elif has_warnings:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
