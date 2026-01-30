#!/usr/bin/env python3
"""
Audit kernel module parameters against expected values.

This script examines runtime kernel module parameters from /sys/module/*/parameters
and compares them against known-good configurations. Useful for detecting
configuration drift, verifying security settings, and ensuring consistent
module tuning across large baremetal fleets.

Key features:
- Lists all module parameters and their current values
- Compares against baseline configuration file
- Supports filtering by module name pattern
- Highlights security-relevant parameters
- Detects non-default values

Use cases:
- Audit network driver parameters (e.g., rx/tx ring sizes)
- Verify security module settings (e.g., lockdown mode)
- Check filesystem module options
- Detect configuration drift between hosts
- Validate performance tuning parameters

Exit codes:
    0 - All parameters match expected values (or no baseline)
    1 - Parameter mismatches or warnings found
    2 - Usage error or /sys/module not available
"""

import argparse
import json
import os
import re
import sys
from typing import Any, Dict, List, Optional, Tuple


# Security-relevant module parameters to highlight
SECURITY_RELEVANT_PARAMS = {
    'lockdown': {'level'},
    'apparmor': {'enabled', 'mode'},
    'selinux': {'enabled', 'enforce'},
    'integrity': {'enabled'},
    'tpm': {'active'},
    'libata': {'allow_tpm'},
    'vfio_iommu_type1': {'allow_unsafe_interrupts'},
    'kvm': {'ignore_msrs', 'allow_unsafe_assigned_interrupts'},
    'kvm_intel': {'nested', 'vmx'},
    'kvm_amd': {'nested', 'sev'},
    'nf_conntrack': {'acct', 'checksum', 'log_invalid'},
    'bluetooth': {'disable_esco', 'disable_ertm'},
    'usb_storage': {'delay_use'},
}

# Performance-relevant module parameters
PERFORMANCE_RELEVANT_PARAMS = {
    'ixgbe': {'max_vfs', 'allow_unsupported_sfp'},
    'i40e': {'max_vfs'},
    'mlx5_core': {'num_of_groups', 'prof_sel'},
    'nvme': {'io_queue_depth', 'poll_queues'},
    'nvme_core': {'io_timeout', 'multipath'},
    'scsi_mod': {'scan', 'use_blk_mq'},
    'dm_mod': {'dm_numa_node'},
    'raid456': {'stripe_cache_size'},
    'md_mod': {'start_ro', 'start_dirty_degraded'},
}


def read_file_content(path: str) -> Optional[str]:
    """Read file content safely."""
    try:
        with open(path, 'r') as f:
            return f.read().strip()
    except (OSError, IOError, PermissionError):
        return None


def get_loaded_modules() -> List[str]:
    """Get list of currently loaded kernel modules."""
    modules = []
    try:
        for entry in os.listdir('/sys/module'):
            module_path = os.path.join('/sys/module', entry)
            if os.path.isdir(module_path):
                modules.append(entry)
    except OSError:
        pass
    return sorted(modules)


def get_module_parameters(module_name: str) -> Dict[str, str]:
    """Get all parameters for a specific module."""
    params = {}
    params_path = f'/sys/module/{module_name}/parameters'

    if not os.path.isdir(params_path):
        return params

    try:
        for param in os.listdir(params_path):
            param_path = os.path.join(params_path, param)
            if os.path.isfile(param_path):
                value = read_file_content(param_path)
                if value is not None:
                    params[param] = value
    except (OSError, PermissionError):
        pass

    return params


def get_module_info(module_name: str) -> Dict[str, Any]:
    """Get module information including version and refcount."""
    info = {
        'name': module_name,
        'version': None,
        'refcount': None,
        'holders': [],
    }

    module_path = f'/sys/module/{module_name}'

    # Get version
    version = read_file_content(f'{module_path}/version')
    if version:
        info['version'] = version

    # Get refcount
    refcount = read_file_content(f'{module_path}/refcount')
    if refcount:
        try:
            info['refcount'] = int(refcount)
        except ValueError:
            pass

    # Get holders (modules that depend on this one)
    holders_path = f'{module_path}/holders'
    if os.path.isdir(holders_path):
        try:
            info['holders'] = os.listdir(holders_path)
        except OSError:
            pass

    return info


def scan_all_modules(module_filter: Optional[str] = None,
                     param_filter: Optional[str] = None) -> List[Dict[str, Any]]:
    """Scan all modules and their parameters."""
    results = []
    module_pattern = re.compile(module_filter, re.IGNORECASE) if module_filter else None
    param_pattern = re.compile(param_filter, re.IGNORECASE) if param_filter else None

    for module_name in get_loaded_modules():
        # Apply module filter
        if module_pattern and not module_pattern.search(module_name):
            continue

        params = get_module_parameters(module_name)
        if not params:
            continue

        # Apply parameter filter
        if param_pattern:
            params = {k: v for k, v in params.items() if param_pattern.search(k)}
            if not params:
                continue

        module_info = get_module_info(module_name)
        module_info['parameters'] = params

        # Tag security and performance relevant parameters
        security_params = SECURITY_RELEVANT_PARAMS.get(module_name, set())
        perf_params = PERFORMANCE_RELEVANT_PARAMS.get(module_name, set())

        param_tags = {}
        for param in params:
            tags = []
            if param in security_params:
                tags.append('security')
            if param in perf_params:
                tags.append('performance')
            if tags:
                param_tags[param] = tags

        if param_tags:
            module_info['param_tags'] = param_tags

        results.append(module_info)

    return results


def load_baseline(baseline_path: str) -> Dict[str, Dict[str, str]]:
    """Load baseline configuration from file."""
    try:
        with open(baseline_path, 'r') as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in baseline file: {e}", file=sys.stderr)
        sys.exit(2)
    except OSError as e:
        print(f"Error: Cannot read baseline file: {e}", file=sys.stderr)
        sys.exit(2)


def compare_with_baseline(modules: List[Dict[str, Any]],
                          baseline: Dict[str, Dict[str, str]]) -> List[Dict[str, Any]]:
    """Compare current parameters with baseline and return differences."""
    differences = []

    for module in modules:
        module_name = module['name']
        if module_name not in baseline:
            continue

        expected_params = baseline[module_name]
        actual_params = module['parameters']

        for param_name, expected_value in expected_params.items():
            actual_value = actual_params.get(param_name)

            if actual_value is None:
                differences.append({
                    'module': module_name,
                    'parameter': param_name,
                    'expected': expected_value,
                    'actual': '(not present)',
                    'status': 'missing'
                })
            elif str(actual_value) != str(expected_value):
                differences.append({
                    'module': module_name,
                    'parameter': param_name,
                    'expected': expected_value,
                    'actual': actual_value,
                    'status': 'mismatch'
                })

    return differences


def generate_baseline(modules: List[Dict[str, Any]]) -> Dict[str, Dict[str, str]]:
    """Generate baseline from current module parameters."""
    baseline = {}
    for module in modules:
        if module['parameters']:
            baseline[module['name']] = module['parameters']
    return baseline


def output_plain(modules: List[Dict[str, Any]], differences: List[Dict[str, Any]],
                 verbose: bool, warn_only: bool, show_security: bool) -> None:
    """Output results in plain text format."""
    if differences:
        print("PARAMETER MISMATCHES DETECTED")
        print("=" * 60)
        for diff in differences:
            status = "MISMATCH" if diff['status'] == 'mismatch' else "MISSING"
            print(f"[{status}] {diff['module']}.{diff['parameter']}")
            print(f"  Expected: {diff['expected']}")
            print(f"  Actual:   {diff['actual']}")
            print()

    if warn_only and not differences:
        print("OK - All parameters match baseline")
        return

    if not warn_only:
        # Filter for security-relevant if requested
        if show_security:
            print("SECURITY-RELEVANT MODULE PARAMETERS")
            print("=" * 60)
            for module in modules:
                if 'param_tags' not in module:
                    continue
                security_params = [p for p, tags in module['param_tags'].items()
                                   if 'security' in tags]
                if security_params:
                    print(f"\n{module['name']}:")
                    for param in security_params:
                        value = module['parameters'].get(param, '(unknown)')
                        print(f"  {param} = {value}")
        else:
            # Show all modules with parameters
            print("KERNEL MODULE PARAMETERS")
            print("=" * 60)

            for module in modules:
                params = module['parameters']
                if not params:
                    continue

                version = f" (v{module['version']})" if module.get('version') else ""
                print(f"\n{module['name']}{version}:")

                if verbose:
                    refcount = module.get('refcount')
                    holders = module.get('holders', [])
                    if refcount is not None:
                        print(f"  [refcount: {refcount}, holders: {', '.join(holders) or 'none'}]")

                for param, value in sorted(params.items()):
                    tags = module.get('param_tags', {}).get(param, [])
                    tag_str = f" [{', '.join(tags)}]" if tags else ""
                    # Truncate long values
                    if len(str(value)) > 50:
                        value = str(value)[:47] + '...'
                    print(f"  {param} = {value}{tag_str}")

    print()

    # Summary
    total_modules = len(modules)
    total_params = sum(len(m['parameters']) for m in modules)
    print(f"Summary: {total_modules} modules with {total_params} parameters")
    if differences:
        print(f"         {len(differences)} parameter mismatches")


def output_json(modules: List[Dict[str, Any]], differences: List[Dict[str, Any]]) -> None:
    """Output results in JSON format."""
    result = {
        'status': 'mismatch' if differences else 'ok',
        'summary': {
            'total_modules': len(modules),
            'total_parameters': sum(len(m['parameters']) for m in modules),
            'mismatches': len(differences),
        },
        'differences': differences,
        'modules': modules,
    }
    print(json.dumps(result, indent=2))


def output_table(modules: List[Dict[str, Any]], differences: List[Dict[str, Any]],
                 show_security: bool) -> None:
    """Output results in table format."""
    if differences:
        print(f"{'Module':<20} {'Parameter':<25} {'Expected':<20} {'Actual':<20}")
        print("-" * 85)
        for diff in differences:
            expected = str(diff['expected'])[:18] if len(str(diff['expected'])) > 18 else diff['expected']
            actual = str(diff['actual'])[:18] if len(str(diff['actual'])) > 18 else diff['actual']
            print(f"{diff['module']:<20} {diff['parameter']:<25} {expected:<20} {actual:<20}")
        print()

    print(f"{'Module':<20} {'Parameter':<25} {'Value':<30} {'Tags':<15}")
    print("-" * 90)

    for module in modules:
        params = module['parameters']
        param_tags = module.get('param_tags', {})

        for param, value in sorted(params.items()):
            tags = param_tags.get(param, [])
            if show_security and 'security' not in tags:
                continue

            value_str = str(value)[:28] if len(str(value)) > 28 else value
            tag_str = ', '.join(tags) if tags else ''
            print(f"{module['name']:<20} {param:<25} {value_str:<30} {tag_str:<15}")


def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Audit kernel module parameters against expected values",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          List all module parameters
  %(prog)s --module nvme            Show only nvme-related modules
  %(prog)s --security               Show security-relevant parameters
  %(prog)s --baseline config.json   Compare against baseline
  %(prog)s --generate-baseline      Output baseline JSON to stdout
  %(prog)s --format json            JSON output for automation

Exit codes:
  0 - No mismatches found (or no baseline provided)
  1 - Parameter mismatches detected
  2 - Usage error or system not available
"""
    )

    parser.add_argument(
        '-f', '--format',
        choices=['plain', 'json', 'table'],
        default='plain',
        help='Output format (default: plain)'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed module information'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show mismatches and warnings'
    )

    parser.add_argument(
        '--module',
        type=str,
        metavar='PATTERN',
        help='Filter modules by name pattern (regex)'
    )

    parser.add_argument(
        '--param',
        type=str,
        metavar='PATTERN',
        help='Filter parameters by name pattern (regex)'
    )

    parser.add_argument(
        '--security',
        action='store_true',
        help='Show only security-relevant parameters'
    )

    parser.add_argument(
        '--baseline',
        type=str,
        metavar='FILE',
        help='Compare against baseline JSON file'
    )

    parser.add_argument(
        '--generate-baseline',
        action='store_true',
        help='Generate baseline JSON from current parameters'
    )

    args = parser.parse_args()

    # Validate regex patterns
    if args.module:
        try:
            re.compile(args.module)
        except re.error as e:
            print(f"Error: Invalid module pattern: {e}", file=sys.stderr)
            sys.exit(2)

    if args.param:
        try:
            re.compile(args.param)
        except re.error as e:
            print(f"Error: Invalid parameter pattern: {e}", file=sys.stderr)
            sys.exit(2)

    # Check if /sys/module is available
    if not os.path.isdir('/sys/module'):
        print("Error: /sys/module not available", file=sys.stderr)
        print("This script requires a Linux kernel with sysfs", file=sys.stderr)
        sys.exit(2)

    # Scan modules
    modules = scan_all_modules(args.module, args.param)

    if not modules:
        if args.format == 'json':
            print(json.dumps({
                'status': 'ok',
                'summary': {'total_modules': 0, 'total_parameters': 0, 'mismatches': 0},
                'message': 'No modules with parameters found'
            }, indent=2))
        else:
            print("No modules with parameters found matching filter")
        sys.exit(0)

    # Generate baseline mode
    if args.generate_baseline:
        baseline = generate_baseline(modules)
        print(json.dumps(baseline, indent=2, sort_keys=True))
        sys.exit(0)

    # Compare with baseline if provided
    differences = []
    if args.baseline:
        baseline = load_baseline(args.baseline)
        differences = compare_with_baseline(modules, baseline)

    # Output based on format
    if args.format == 'json':
        output_json(modules, differences)
    elif args.format == 'table':
        output_table(modules, differences, args.security)
    else:
        output_plain(modules, differences, args.verbose, args.warn_only, args.security)

    # Exit code based on findings
    if differences:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()
