#!/usr/bin/env python3
"""
Monitor kernel taint status for baremetal systems.

Kernel taints indicate various conditions that may affect kernel stability,
supportability, or debuggability. This script monitors and reports on kernel
taint flags, which are critical for:
- Fleet consistency (ensuring all servers are "clean")
- Debugging kernel issues (taints indicate crashes, MCEs, etc.)
- Compliance auditing (detecting proprietary/unsigned modules)
- Operations alerting (detecting changes from expected baseline)

Taint categories:
- Proprietary: Non-GPL modules loaded (nvidia, etc.)
- Stability: Forced module operations, crashes, soft lockups
- Hardware: Machine check exceptions, bad memory pages
- Security: Unsigned modules, userspace /dev/mem writes
- Development: Staging drivers, live patches, kernel warnings

Exit codes:
    0 - Kernel is untainted (clean)
    1 - Kernel is tainted (warnings/issues found)
    2 - Usage error or unable to read taint status
"""

import argparse
import json
import sys
from datetime import datetime

# Kernel taint bit definitions (from Documentation/admin-guide/tainted-kernels.rst)
TAINT_FLAGS = {
    0:  ('P', 'proprietary', 'Proprietary module loaded', 'warning'),
    1:  ('F', 'forced', 'Module force loaded (modprobe -f)', 'warning'),
    2:  ('S', 'smp_unsafe', 'SMP-unsafe module loaded', 'critical'),
    3:  ('R', 'forced_unload', 'Module force unloaded (rmmod -f)', 'warning'),
    4:  ('M', 'machine_check', 'Machine check exception occurred', 'critical'),
    5:  ('B', 'bad_page', 'Bad memory page reference', 'critical'),
    6:  ('U', 'userspace', 'Userspace wrote to /dev/mem', 'warning'),
    7:  ('D', 'oops', 'Kernel oops has occurred', 'critical'),
    8:  ('A', 'acpi', 'ACPI table overridden by user', 'info'),
    9:  ('W', 'warning', 'Kernel warning has occurred', 'warning'),
    10: ('C', 'staging', 'Staging driver loaded', 'info'),
    11: ('I', 'firmware', 'Firmware bug workaround applied', 'info'),
    12: ('O', 'out_of_tree', 'Out-of-tree module loaded', 'warning'),
    13: ('E', 'unsigned', 'Unsigned module loaded', 'warning'),
    14: ('L', 'softlockup', 'Soft lockup has occurred', 'critical'),
    15: ('K', 'live_patch', 'Kernel live patch applied', 'info'),
    16: ('X', 'auxiliary', 'Auxiliary taint (reserved)', 'info'),
    17: ('T', 'randstruct', 'Randstruct randomization', 'info'),
    18: ('N', 'test', 'Test taint (for testing only)', 'info'),
}

# Severity levels
SEVERITY_ORDER = {'critical': 0, 'warning': 1, 'info': 2}


def read_taint_value():
    """Read the kernel taint value from /proc/sys/kernel/tainted"""
    try:
        with open('/proc/sys/kernel/tainted', 'r') as f:
            return int(f.read().strip())
    except FileNotFoundError:
        print("Error: /proc/sys/kernel/tainted not found", file=sys.stderr)
        print("This system may not expose kernel taint information", file=sys.stderr)
        sys.exit(2)
    except ValueError as e:
        print(f"Error: Unable to parse taint value: {e}", file=sys.stderr)
        sys.exit(2)
    except PermissionError:
        print("Error: Permission denied reading /proc/sys/kernel/tainted",
              file=sys.stderr)
        sys.exit(2)
    except IOError as e:
        print(f"Error reading taint status: {e}", file=sys.stderr)
        sys.exit(2)


def decode_taint_value(taint_value):
    """Decode the taint bitmask into individual flags"""
    taints = []

    if taint_value == 0:
        return taints

    for bit, (flag, name, description, severity) in TAINT_FLAGS.items():
        if taint_value & (1 << bit):
            taints.append({
                'bit': bit,
                'flag': flag,
                'name': name,
                'description': description,
                'severity': severity,
            })

    # Sort by severity (critical first)
    taints.sort(key=lambda t: SEVERITY_ORDER.get(t['severity'], 99))

    return taints


def get_taint_string(taint_value):
    """Get the taint string representation (e.g., 'P--S-M-')"""
    if taint_value == 0:
        return ''

    chars = []
    for bit in range(19):  # 0-18 are defined
        if bit in TAINT_FLAGS:
            flag = TAINT_FLAGS[bit][0]
            if taint_value & (1 << bit):
                chars.append(flag)
            else:
                chars.append('-')
        else:
            chars.append('-')

    return ''.join(chars)


def collect_data(expected_taints=None):
    """Collect kernel taint data"""
    taint_value = read_taint_value()
    taints = decode_taint_value(taint_value)
    taint_string = get_taint_string(taint_value)

    data = {
        'timestamp': datetime.now().isoformat(),
        'taint_value': taint_value,
        'taint_string': taint_string,
        'is_tainted': taint_value != 0,
        'taints': taints,
        'summary': {
            'total': len(taints),
            'critical': sum(1 for t in taints if t['severity'] == 'critical'),
            'warning': sum(1 for t in taints if t['severity'] == 'warning'),
            'info': sum(1 for t in taints if t['severity'] == 'info'),
        },
        'expected_taints': expected_taints,
        'unexpected_taints': [],
    }

    # Check for unexpected taints if baseline provided
    if expected_taints is not None:
        expected_set = set(expected_taints)
        current_set = set(t['name'] for t in taints)
        unexpected = current_set - expected_set
        data['unexpected_taints'] = list(unexpected)

    return data


def output_plain(data, verbose=False, warn_only=False):
    """Output in plain text format"""
    if not data['is_tainted']:
        if not warn_only:
            print("Kernel taint status: CLEAN (not tainted)")
        return

    print(f"Kernel taint status: TAINTED")
    print(f"Taint value: {data['taint_value']}")
    print(f"Taint string: {data['taint_string']}")
    print()

    # Summary
    print(f"Summary: {data['summary']['total']} taint(s) active")
    if data['summary']['critical'] > 0:
        print(f"  Critical: {data['summary']['critical']}")
    if data['summary']['warning'] > 0:
        print(f"  Warning: {data['summary']['warning']}")
    if data['summary']['info'] > 0:
        print(f"  Info: {data['summary']['info']}")
    print()

    # Details
    print("Active taints:")
    print("-" * 60)
    for taint in data['taints']:
        severity_marker = "!!!" if taint['severity'] == 'critical' else \
                         " ! " if taint['severity'] == 'warning' else "   "
        print(f"{severity_marker}[{taint['flag']}] {taint['name']}: {taint['description']}")
        if verbose:
            print(f"      Bit: {taint['bit']}, Severity: {taint['severity']}")

    # Unexpected taints
    if data['unexpected_taints']:
        print()
        print("Unexpected taints (not in baseline):")
        for name in data['unexpected_taints']:
            print(f"  - {name}")


def output_json(data):
    """Output in JSON format"""
    print(json.dumps(data, indent=2))


def output_table(data, warn_only=False):
    """Output in table format"""
    if not data['is_tainted']:
        if not warn_only:
            print(f"{'Status':<12} {'Value':<10} {'Flags':<20}")
            print("-" * 42)
            print(f"{'CLEAN':<12} {'0':<10} {'(none)':<20}")
        return

    print(f"{'Flag':<6} {'Name':<16} {'Severity':<10} {'Description':<35}")
    print("=" * 67)

    for taint in data['taints']:
        print(f"{taint['flag']:<6} {taint['name']:<16} "
              f"{taint['severity']:<10} {taint['description'][:35]:<35}")


def parse_expected_taints(expected_str):
    """Parse comma-separated expected taint names"""
    if not expected_str:
        return None

    taints = [t.strip().lower() for t in expected_str.split(',')]
    # Validate taint names
    valid_names = set(info[1] for info in TAINT_FLAGS.values())

    for t in taints:
        if t not in valid_names:
            print(f"Warning: Unknown taint name '{t}'", file=sys.stderr)
            print(f"Valid names: {', '.join(sorted(valid_names))}", file=sys.stderr)

    return taints


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Monitor kernel taint status for baremetal systems',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Taint Flags:
  P - Proprietary module loaded (nvidia, etc.)
  F - Module force loaded
  S - SMP-unsafe module
  R - Module force unloaded
  M - Machine check exception (hardware error)
  B - Bad memory page reference
  U - Userspace wrote to /dev/mem
  D - Kernel oops occurred
  A - ACPI table overridden
  W - Kernel warning occurred
  C - Staging driver loaded
  I - Firmware bug workaround applied
  O - Out-of-tree module loaded
  E - Unsigned module loaded
  L - Soft lockup occurred
  K - Kernel live patch applied

Examples:
  %(prog)s                           # Check taint status
  %(prog)s --format json             # JSON output for automation
  %(prog)s --expected proprietary    # Alert on unexpected taints
  %(prog)s -w                        # Only output if tainted

Exit codes:
  0 - Kernel is clean (untainted)
  1 - Kernel is tainted
  2 - Error reading taint status
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
        help='Show detailed information'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show output if kernel is tainted'
    )

    parser.add_argument(
        '--expected',
        metavar='TAINTS',
        help='Comma-separated list of expected taint names (e.g., "proprietary,out_of_tree"). '
             'Script will alert on unexpected taints not in this list.'
    )

    parser.add_argument(
        '--critical-only',
        action='store_true',
        help='Only exit with error code 1 for critical taints '
             '(oops, machine_check, bad_page, softlockup, smp_unsafe)'
    )

    args = parser.parse_args()

    # Parse expected taints
    expected_taints = parse_expected_taints(args.expected)

    # Collect data
    data = collect_data(expected_taints=expected_taints)

    # Output
    if args.format == 'json':
        output_json(data)
    elif args.format == 'table':
        output_table(data, warn_only=args.warn_only)
    else:
        output_plain(data, verbose=args.verbose, warn_only=args.warn_only)

    # Determine exit code
    if not data['is_tainted']:
        sys.exit(0)

    if args.critical_only:
        # Only exit 1 for critical taints
        if data['summary']['critical'] > 0:
            sys.exit(1)
        else:
            sys.exit(0)
    else:
        # Any taint causes exit 1
        sys.exit(1)


if __name__ == "__main__":
    main()
