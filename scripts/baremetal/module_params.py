#!/usr/bin/env python3
# boxctl:
#   category: baremetal/kernel
#   tags: [kernel, modules, parameters, security, performance, audit]
#   requires: []
#   privilege: user
#   related: [kernel_config, kernel_module_audit, kernel_security]
#   brief: Audit kernel module parameters against expected values

"""
Audit kernel module parameters against expected values.

Examines runtime kernel module parameters from /sys/module/*/parameters and
compares them against known-good configurations. Useful for detecting
configuration drift, verifying security settings, and ensuring consistent
module tuning across large baremetal fleets.

Key features:
- Lists all module parameters and their current values
- Compares against baseline configuration file
- Supports filtering by module name pattern
- Highlights security-relevant parameters
- Detects non-default values

Exit codes:
    0: All parameters match expected values (or no baseline)
    1: Parameter mismatches or warnings found
    2: Error (/sys/module not available or usage error)
"""

import argparse
import json
import os
import re
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


# Security-relevant module parameters to highlight
SECURITY_RELEVANT_PARAMS = {
    "lockdown": {"level"},
    "apparmor": {"enabled", "mode"},
    "selinux": {"enabled", "enforce"},
    "integrity": {"enabled"},
    "tpm": {"active"},
    "libata": {"allow_tpm"},
    "vfio_iommu_type1": {"allow_unsafe_interrupts"},
    "kvm": {"ignore_msrs", "allow_unsafe_assigned_interrupts"},
    "kvm_intel": {"nested", "vmx"},
    "kvm_amd": {"nested", "sev"},
    "nf_conntrack": {"acct", "checksum", "log_invalid"},
    "bluetooth": {"disable_esco", "disable_ertm"},
    "usb_storage": {"delay_use"},
}

# Performance-relevant module parameters
PERFORMANCE_RELEVANT_PARAMS = {
    "ixgbe": {"max_vfs", "allow_unsupported_sfp"},
    "i40e": {"max_vfs"},
    "mlx5_core": {"num_of_groups", "prof_sel"},
    "nvme": {"io_queue_depth", "poll_queues"},
    "nvme_core": {"io_timeout", "multipath"},
    "scsi_mod": {"scan", "use_blk_mq"},
    "dm_mod": {"dm_numa_node"},
    "raid456": {"stripe_cache_size"},
    "md_mod": {"start_ro", "start_dirty_degraded"},
}


def read_file_content(path: str) -> str | None:
    """Read file content safely."""
    try:
        with open(path, "r") as f:
            return f.read().strip()
    except (OSError, IOError, PermissionError):
        return None


def get_loaded_modules() -> list[str]:
    """Get list of currently loaded kernel modules."""
    modules = []
    try:
        for entry in os.listdir("/sys/module"):
            module_path = os.path.join("/sys/module", entry)
            if os.path.isdir(module_path):
                modules.append(entry)
    except OSError:
        pass
    return sorted(modules)


def get_module_parameters(module_name: str) -> dict[str, str]:
    """Get all parameters for a specific module."""
    params = {}
    params_path = f"/sys/module/{module_name}/parameters"

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


def get_module_info(module_name: str) -> dict[str, Any]:
    """Get module information including version and refcount."""
    info = {
        "name": module_name,
        "version": None,
        "refcount": None,
        "holders": [],
    }

    module_path = f"/sys/module/{module_name}"

    # Get version
    version = read_file_content(f"{module_path}/version")
    if version:
        info["version"] = version

    # Get refcount
    refcount = read_file_content(f"{module_path}/refcount")
    if refcount:
        try:
            info["refcount"] = int(refcount)
        except ValueError:
            pass

    # Get holders (modules that depend on this one)
    holders_path = f"{module_path}/holders"
    if os.path.isdir(holders_path):
        try:
            info["holders"] = os.listdir(holders_path)
        except OSError:
            pass

    return info


def scan_all_modules(
    module_filter: str | None = None, param_filter: str | None = None
) -> list[dict[str, Any]]:
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
        module_info["parameters"] = params

        # Tag security and performance relevant parameters
        security_params = SECURITY_RELEVANT_PARAMS.get(module_name, set())
        perf_params = PERFORMANCE_RELEVANT_PARAMS.get(module_name, set())

        param_tags = {}
        for param in params:
            tags = []
            if param in security_params:
                tags.append("security")
            if param in perf_params:
                tags.append("performance")
            if tags:
                param_tags[param] = tags

        if param_tags:
            module_info["param_tags"] = param_tags

        results.append(module_info)

    return results


def load_baseline(baseline_path: str) -> dict[str, dict[str, str]]:
    """Load baseline configuration from file."""
    try:
        with open(baseline_path, "r") as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in baseline file: {e}")
    except OSError as e:
        raise ValueError(f"Cannot read baseline file: {e}")


def compare_with_baseline(
    modules: list[dict[str, Any]], baseline: dict[str, dict[str, str]]
) -> list[dict[str, Any]]:
    """Compare current parameters with baseline and return differences."""
    differences = []

    for module in modules:
        module_name = module["name"]
        if module_name not in baseline:
            continue

        expected_params = baseline[module_name]
        actual_params = module["parameters"]

        for param_name, expected_value in expected_params.items():
            actual_value = actual_params.get(param_name)

            if actual_value is None:
                differences.append(
                    {
                        "module": module_name,
                        "parameter": param_name,
                        "expected": expected_value,
                        "actual": "(not present)",
                        "status": "missing",
                    }
                )
            elif str(actual_value) != str(expected_value):
                differences.append(
                    {
                        "module": module_name,
                        "parameter": param_name,
                        "expected": expected_value,
                        "actual": actual_value,
                        "status": "mismatch",
                    }
                )

    return differences


def generate_baseline(modules: list[dict[str, Any]]) -> dict[str, dict[str, str]]:
    """Generate baseline from current module parameters."""
    baseline = {}
    for module in modules:
        if module["parameters"]:
            baseline[module["name"]] = module["parameters"]
    return baseline


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = no mismatches, 1 = mismatches found, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Audit kernel module parameters against expected values"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Show detailed module information"
    )
    parser.add_argument(
        "--format", choices=["plain", "json"], default="plain", help="Output format"
    )
    parser.add_argument(
        "-w", "--warn-only", action="store_true", help="Only show mismatches and warnings"
    )
    parser.add_argument(
        "--module", type=str, metavar="PATTERN", help="Filter modules by name pattern (regex)"
    )
    parser.add_argument(
        "--param", type=str, metavar="PATTERN", help="Filter parameters by name pattern (regex)"
    )
    parser.add_argument(
        "--security", action="store_true", help="Show only security-relevant parameters"
    )
    parser.add_argument(
        "--baseline", type=str, metavar="FILE", help="Compare against baseline JSON file"
    )
    parser.add_argument(
        "--generate-baseline",
        action="store_true",
        help="Generate baseline JSON from current parameters",
    )
    opts = parser.parse_args(args)

    # Validate regex patterns
    if opts.module:
        try:
            re.compile(opts.module)
        except re.error as e:
            output.error(f"Invalid module pattern: {e}")
            return 2

    if opts.param:
        try:
            re.compile(opts.param)
        except re.error as e:
            output.error(f"Invalid parameter pattern: {e}")
            return 2

    # Check if /sys/module is available
    if not os.path.isdir("/sys/module"):
        output.error("/sys/module not available. This script requires Linux with sysfs.")
        return 2

    # Scan modules
    modules = scan_all_modules(opts.module, opts.param)

    if not modules:
        result_data = {
            "status": "ok",
            "summary": {"total_modules": 0, "total_parameters": 0, "mismatches": 0},
            "message": "No modules with parameters found",
            "modules": [],
            "differences": [],
        }
        output.emit(result_data)

        if opts.format == "json":
            print(json.dumps(result_data, indent=2))
        else:
            print("No modules with parameters found matching filter")
        return 0

    # Generate baseline mode
    if opts.generate_baseline:
        baseline = generate_baseline(modules)
        print(json.dumps(baseline, indent=2, sort_keys=True))
        return 0

    # Compare with baseline if provided
    differences = []
    if opts.baseline:
        try:
            baseline = load_baseline(opts.baseline)
            differences = compare_with_baseline(modules, baseline)
        except ValueError as e:
            output.error(str(e))
            return 2

    # Build result
    result_data = {
        "status": "mismatch" if differences else "ok",
        "summary": {
            "total_modules": len(modules),
            "total_parameters": sum(len(m["parameters"]) for m in modules),
            "mismatches": len(differences),
        },
        "differences": differences,
        "modules": modules,
    }

    output.emit(result_data)

    # Output based on format
    if opts.format == "json":
        print(json.dumps(result_data, indent=2))
    else:
        if differences:
            print("PARAMETER MISMATCHES DETECTED")
            print("=" * 60)
            for diff in differences:
                status = "MISMATCH" if diff["status"] == "mismatch" else "MISSING"
                print(f"[{status}] {diff['module']}.{diff['parameter']}")
                print(f"  Expected: {diff['expected']}")
                print(f"  Actual:   {diff['actual']}")
                print()

        if opts.warn_only and not differences:
            print("OK - All parameters match baseline")
        elif not opts.warn_only:
            # Filter for security-relevant if requested
            if opts.security:
                print("SECURITY-RELEVANT MODULE PARAMETERS")
                print("=" * 60)
                for module in modules:
                    if "param_tags" not in module:
                        continue
                    security_params = [
                        p for p, tags in module["param_tags"].items() if "security" in tags
                    ]
                    if security_params:
                        print(f"\n{module['name']}:")
                        for param in security_params:
                            value = module["parameters"].get(param, "(unknown)")
                            print(f"  {param} = {value}")
            else:
                # Show all modules with parameters
                print("KERNEL MODULE PARAMETERS")
                print("=" * 60)

                for module in modules:
                    params = module["parameters"]
                    if not params:
                        continue

                    version = f" (v{module['version']})" if module.get("version") else ""
                    print(f"\n{module['name']}{version}:")

                    if opts.verbose:
                        refcount = module.get("refcount")
                        holders = module.get("holders", [])
                        if refcount is not None:
                            print(
                                f"  [refcount: {refcount}, holders: {', '.join(holders) or 'none'}]"
                            )

                    for param, value in sorted(params.items()):
                        tags = module.get("param_tags", {}).get(param, [])
                        tag_str = f" [{', '.join(tags)}]" if tags else ""
                        # Truncate long values
                        if len(str(value)) > 50:
                            value = str(value)[:47] + "..."
                        print(f"  {param} = {value}{tag_str}")

            print()

            # Summary
            total_modules = len(modules)
            total_params = sum(len(m["parameters"]) for m in modules)
            print(f"Summary: {total_modules} modules with {total_params} parameters")
            if differences:
                print(f"         {len(differences)} parameter mismatches")

    output.set_summary(
        f"modules={len(modules)}, params={result_data['summary']['total_parameters']}, "
        f"mismatches={len(differences)}"
    )

    # Exit code based on findings
    return 1 if differences else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
