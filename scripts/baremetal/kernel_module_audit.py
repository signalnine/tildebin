#!/usr/bin/env python3
# boxctl:
#   category: baremetal/kernel
#   tags: [health, kernel, modules, security, compliance]
#   requires: [lsmod, modinfo]
#   brief: Audit loaded kernel modules for security and compliance

"""
Audit loaded kernel modules for security and compliance.

Identifies unsigned modules, out-of-tree modules, modules that taint the kernel,
and potentially problematic drivers.

Exit codes:
    0: All modules are signed and in-tree (healthy)
    1: Warnings detected (unsigned or out-of-tree modules found)
    2: Usage error or missing dependency
"""

import argparse
import json
from datetime import datetime, timezone

from boxctl.core.context import Context
from boxctl.core.output import Output


# Deprecated modules that should be noted
DEPRECATED_MODULES = ["floppy", "parport", "parport_pc", "lp", "pcspkr"]

# Known problematic modules
PROBLEMATIC_MODULES = {
    "nouveau": "Open-source NVIDIA driver (consider nvidia for production)",
    "r8169": "Realtek driver (known issues with certain NICs)",
}

# Module category tags
VIRT_MODULES = ["kvm", "kvm_intel", "kvm_amd", "vhost_net", "vhost_scsi"]
SECURITY_MODULES = ["apparmor", "selinux", "tomoyo", "smack"]
FS_MODULES = ["ext4", "xfs", "btrfs", "zfs", "nfs", "cifs", "fuse"]


def parse_lsmod_output(lsmod_output: str) -> list[dict]:
    """Parse lsmod output into module list."""
    modules = []
    lines = lsmod_output.strip().split("\n")

    if len(lines) < 2:
        return modules

    # Skip header line
    for line in lines[1:]:
        parts = line.split()
        if len(parts) >= 3:
            module = {
                "name": parts[0],
                "size": int(parts[1]),
                "used_by_count": int(parts[2]),
                "used_by": parts[3].split(",") if len(parts) > 3 and parts[3] != "-" else [],
                "flags": [],
                "issues": [],
            }
            modules.append(module)

    return modules


def parse_modinfo_output(modinfo_output: str) -> dict:
    """Parse modinfo output into info dict."""
    info = {}

    for line in modinfo_output.split("\n"):
        if ":" in line:
            key, value = line.split(":", 1)
            key = key.strip().lower()
            value = value.strip()

            if key == "filename":
                info["filename"] = value
            elif key == "version":
                info["version"] = value
            elif key == "license":
                info["license"] = value
            elif key == "description":
                info["description"] = value
            elif key == "author":
                info["author"] = value
            elif key == "srcversion":
                info["srcversion"] = value
            elif key == "vermagic":
                info["vermagic"] = value
            elif key == "sig_id":
                info["signed"] = True
            elif key == "signer":
                info["signer"] = value
            elif key == "sig_key":
                info["sig_key"] = value
            elif key == "intree":
                info["intree"] = value.lower() == "y"

    # Determine signed status
    if "signer" in info or "sig_key" in info:
        info["signed"] = True
    elif "signed" not in info:
        info["signed"] = False

    # Determine in-tree status from filename
    if "intree" not in info:
        filename = info.get("filename", "")
        if "/kernel/" in filename or "/updates/" in filename:
            info["intree"] = True
        elif "/extra/" in filename or "/weak-updates/" in filename:
            info["intree"] = False
        else:
            info["intree"] = None

    return info


def analyze_module(module: dict, modinfo: dict, check_signatures: bool = True) -> dict:
    """Analyze a module for potential issues."""
    issues = []
    flags = []

    license_val = modinfo.get("license", "").upper()
    filename = modinfo.get("filename", "")

    # Check for proprietary license
    proprietary_licenses = ["PROPRIETARY", "NVIDIA", "CLOSED"]
    if any(p in license_val for p in proprietary_licenses):
        flags.append("proprietary")
        issues.append("Proprietary license may taint kernel")

    # Check for unsigned module (only if we actually checked signatures)
    if check_signatures and modinfo and not modinfo.get("signed", False):
        flags.append("unsigned")
        issues.append("Module is not signed")

    # Check for out-of-tree module (only if we have modinfo data)
    if modinfo and modinfo.get("intree") is False:
        flags.append("out-of-tree")
        issues.append("Module is out-of-tree (not from kernel source)")

    # Check for staging drivers
    if "/staging/" in filename:
        flags.append("staging")
        issues.append("Staging driver (experimental, may be unstable)")

    # Check for deprecated modules
    if module["name"] in DEPRECATED_MODULES:
        flags.append("deprecated")
        issues.append("Deprecated/legacy module")

    # Check for known problematic modules
    if module["name"] in PROBLEMATIC_MODULES:
        flags.append("problematic")
        issues.append(PROBLEMATIC_MODULES[module["name"]])

    # Add category flags
    if module["name"] in VIRT_MODULES:
        flags.append("virtualization")
    if module["name"] in SECURITY_MODULES:
        flags.append("security")
    if module["name"] in FS_MODULES:
        flags.append("filesystem")

    module["flags"] = flags
    module["issues"] = issues
    module["info"] = modinfo

    return module


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = all healthy, 1 = issues found, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Audit loaded kernel modules for security and compliance"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed output")
    parser.add_argument(
        "--format", choices=["plain", "json"], default="plain", help="Output format"
    )
    parser.add_argument(
        "-a", "--all", action="store_true", help="Show all modules, not just those with issues"
    )
    parser.add_argument(
        "-w", "--warn-only", action="store_true", help="Only show modules with warnings"
    )
    parser.add_argument(
        "--no-signature-check",
        action="store_true",
        help="Skip signature verification (faster but less thorough)",
    )
    opts = parser.parse_args(args)

    # Check for required tools
    if not context.check_tool("lsmod"):
        output.error("lsmod not found")
        return 2

    # Get kernel version
    try:
        uname_result = context.run(["uname", "-r"])
        kernel_version = uname_result.stdout.strip()
    except Exception:
        kernel_version = "unknown"

    # Get taint status
    try:
        taint_content = context.read_file("/proc/sys/kernel/tainted")
        taint_value = int(taint_content.strip())
    except (FileNotFoundError, ValueError, IOError):
        taint_value = 0

    # Get loaded modules
    try:
        lsmod_result = context.run(["lsmod"])
        modules = parse_lsmod_output(lsmod_result.stdout)
    except Exception as e:
        output.error(f"Failed to run lsmod: {e}")
        return 2

    # Analyze modules
    summary = {
        "total": 0,
        "unsigned": 0,
        "out_of_tree": 0,
        "proprietary": 0,
        "staging": 0,
        "with_issues": 0,
    }

    for module in modules:
        modinfo = {}
        if not opts.no_signature_check and context.check_tool("modinfo"):
            try:
                modinfo_result = context.run(["modinfo", module["name"]], check=False)
                modinfo = parse_modinfo_output(modinfo_result.stdout)
            except Exception:
                pass

        module = analyze_module(module, modinfo, check_signatures=not opts.no_signature_check)

        # Update summary
        summary["total"] += 1
        if "unsigned" in module["flags"]:
            summary["unsigned"] += 1
        if "out-of-tree" in module["flags"]:
            summary["out_of_tree"] += 1
        if "proprietary" in module["flags"]:
            summary["proprietary"] += 1
        if "staging" in module["flags"]:
            summary["staging"] += 1
        if module["issues"]:
            summary["with_issues"] += 1

    # Filter modules for output
    if opts.warn_only:
        output_modules = [m for m in modules if m["issues"]]
    elif opts.all:
        output_modules = modules
    else:
        output_modules = [m for m in modules if m["issues"]]

    # Sort by issue count
    output_modules.sort(key=lambda m: len(m["issues"]), reverse=True)

    # Build result
    result = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "kernel_version": kernel_version,
        "taint_value": taint_value,
        "summary": summary,
        "modules": output_modules,
    }

    # Output handling
    if opts.format == "json":
        print(json.dumps(result, indent=2))
    else:
        lines = []
        lines.append("Kernel Module Audit Report")
        lines.append("=" * 60)
        lines.append(f"Kernel Version: {kernel_version}")
        lines.append("")

        if taint_value == 0:
            lines.append("Kernel Taint: None (clean)")
        else:
            lines.append(f"Kernel Taint: {taint_value} (tainted)")
        lines.append("")

        lines.append("Summary:")
        lines.append(f"  Total modules loaded: {summary['total']}")
        lines.append(f"  Unsigned modules: {summary['unsigned']}")
        lines.append(f"  Out-of-tree modules: {summary['out_of_tree']}")
        lines.append(f"  Proprietary modules: {summary['proprietary']}")
        lines.append(f"  Staging drivers: {summary['staging']}")
        lines.append(f"  Modules with issues: {summary['with_issues']}")
        lines.append("")

        if output_modules:
            lines.append("Module Details:")
            lines.append("-" * 60)

            for module in output_modules:
                flags_str = ",".join(module["flags"]) if module["flags"] else "ok"
                lines.append(f"{module['name']} ({flags_str})")

                if opts.verbose:
                    info = module.get("info", {})
                    if info.get("license"):
                        lines.append(f"  License: {info['license']}")
                    if info.get("version"):
                        lines.append(f"  Version: {info['version']}")
                    if info.get("description"):
                        lines.append(f"  Description: {info['description'][:60]}")
                    used_by_str = ",".join(module["used_by"]) if module["used_by"] else "none"
                    lines.append(f"  Size: {module['size']} bytes, Used by: {used_by_str}")

                for issue in module["issues"]:
                    lines.append(f"  [!] {issue}")

                lines.append("")

        print("\n".join(lines))

    # Store data for output helper
    output.emit(result)
    output.set_summary(f"total={summary['total']}, issues={summary['with_issues']}")

    return 1 if summary["with_issues"] > 0 else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
