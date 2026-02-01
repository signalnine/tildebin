#!/usr/bin/env python3
# boxctl:
#   category: baremetal/kernel
#   tags: [health, kernel, security, compliance, boot]
#   brief: Audit kernel boot parameters for security and best practices

"""
Audit kernel command line parameters for security and best practices.

Checks security hardening (IOMMU, KPTI, KASLR, CPU mitigations),
performance tuning, debug options, and known problematic parameters.

Exit codes:
    0: All parameters pass audit (or info-only findings)
    1: Warnings or issues detected
    2: Usage error or /proc/cmdline not available
"""

import argparse
import json
from datetime import datetime, timezone
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


# Security-related parameter checks
SECURITY_CHECKS = {
    "iommu": {
        "description": "IOMMU for DMA attack protection",
        "recommended": ["on", "force"],
        "severity": "WARNING",
        "recommendation": "Enable with iommu=on or intel_iommu=on/amd_iommu=on",
    },
    "intel_iommu": {
        "description": "Intel IOMMU/VT-d for DMA protection",
        "recommended": ["on"],
        "severity": "WARNING",
        "recommendation": "Enable with intel_iommu=on for Intel systems",
    },
    "amd_iommu": {
        "description": "AMD IOMMU for DMA protection",
        "recommended": ["on"],
        "severity": "WARNING",
        "recommendation": "Enable with amd_iommu=on for AMD systems",
    },
    "mitigations": {
        "description": "CPU vulnerability mitigations",
        "bad_values": ["off"],
        "severity": "CRITICAL",
        "recommendation": "Do not disable CPU mitigations in production",
    },
    "spectre_v2": {
        "description": "Spectre v2 mitigation",
        "bad_values": ["off"],
        "severity": "CRITICAL",
        "recommendation": "Do not disable Spectre mitigations",
    },
    "pti": {
        "description": "Page Table Isolation (Meltdown mitigation)",
        "bad_values": ["off"],
        "severity": "CRITICAL",
        "recommendation": "Do not disable PTI/KPTI in production",
    },
    "nokaslr": {
        "description": "KASLR disabled",
        "presence_is_bad": True,
        "severity": "WARNING",
        "recommendation": "Remove nokaslr to enable kernel address randomization",
    },
}

# Debug parameters that should not be in production
DEBUG_PARAMS = {
    "debug": {
        "description": "Kernel debug mode",
        "presence_is_bad": True,
        "severity": "WARNING",
        "recommendation": "Remove debug parameter in production",
    },
    "initcall_debug": {
        "description": "Init call debugging",
        "presence_is_bad": True,
        "severity": "WARNING",
        "recommendation": "Remove initcall_debug in production",
    },
    "norandmaps": {
        "description": "Disable ASLR for user processes",
        "presence_is_bad": True,
        "severity": "WARNING",
        "recommendation": "Remove norandmaps to enable ASLR",
    },
}

# Performance-related parameters (informational)
PERFORMANCE_PARAMS = {
    "transparent_hugepage": {
        "description": "Transparent Huge Pages",
        "severity": "INFO",
        "recommendation": "THP=never often recommended for databases",
    },
    "hugepages": {
        "description": "Number of huge pages",
        "severity": "INFO",
        "recommendation": "Pre-allocated huge pages configured",
    },
    "isolcpus": {
        "description": "Isolated CPUs for dedicated workloads",
        "severity": "INFO",
        "recommendation": "Useful for real-time or latency-sensitive applications",
    },
    "nohz_full": {
        "description": "Full tickless CPUs",
        "severity": "INFO",
        "recommendation": "Reduces interrupts on specified CPUs",
    },
}


def parse_cmdline(cmdline: str) -> dict[str, str | None]:
    """Parse kernel command line into parameter dictionary."""
    params: dict[str, str | None] = {}
    tokens = cmdline.split()

    for token in tokens:
        if "=" in token:
            key, value = token.split("=", 1)
            params[key] = value
        else:
            params[token] = None

    return params


def check_security(params: dict[str, str | None]) -> list[dict[str, Any]]:
    """Check security-related parameters."""
    findings = []

    for param, check in SECURITY_CHECKS.items():
        value = params.get(param)

        if check.get("presence_is_bad") and param in params:
            findings.append(
                {
                    "parameter": param,
                    "value": value,
                    "category": "security",
                    "severity": check["severity"],
                    "description": check["description"],
                    "issue": "Parameter should not be present",
                    "recommendation": check["recommendation"],
                }
            )
        elif "bad_values" in check and value in check["bad_values"]:
            findings.append(
                {
                    "parameter": param,
                    "value": value,
                    "category": "security",
                    "severity": check["severity"],
                    "description": check["description"],
                    "issue": f"Insecure value: {value}",
                    "recommendation": check["recommendation"],
                }
            )

    return findings


def check_debug(params: dict[str, str | None]) -> list[dict[str, Any]]:
    """Check for debug parameters."""
    findings = []

    for param, check in DEBUG_PARAMS.items():
        if param in params:
            findings.append(
                {
                    "parameter": param,
                    "value": params.get(param),
                    "category": "debug",
                    "severity": check["severity"],
                    "description": check["description"],
                    "issue": "Debug parameter present",
                    "recommendation": check["recommendation"],
                }
            )

    return findings


def check_performance(params: dict[str, str | None]) -> list[dict[str, Any]]:
    """Check performance-related parameters (informational)."""
    findings = []

    for param, check in PERFORMANCE_PARAMS.items():
        if param in params:
            findings.append(
                {
                    "parameter": param,
                    "value": params.get(param),
                    "category": "performance",
                    "severity": check["severity"],
                    "description": check["description"],
                    "issue": "Performance tuning parameter",
                    "recommendation": check["recommendation"],
                }
            )

    return findings


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = no issues, 1 = issues found, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Audit kernel command line parameters for security and best practices"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed output")
    parser.add_argument(
        "--format", choices=["plain", "json"], default="plain", help="Output format"
    )
    parser.add_argument(
        "-w", "--warn-only", action="store_true", help="Only show warnings and critical issues"
    )
    parser.add_argument(
        "--skip-security", action="store_true", help="Skip security checks"
    )
    parser.add_argument(
        "--skip-debug", action="store_true", help="Skip debug parameter checks"
    )
    parser.add_argument(
        "--skip-performance", action="store_true", help="Skip performance parameter checks"
    )
    opts = parser.parse_args(args)

    # Read cmdline
    try:
        cmdline = context.read_file("/proc/cmdline").strip()
    except FileNotFoundError:
        output.error("/proc/cmdline not found")
        return 2
    except IOError as e:
        output.error(f"Unable to read /proc/cmdline: {e}")
        return 2

    params = parse_cmdline(cmdline)

    # Collect findings
    findings: list[dict[str, Any]] = []

    if not opts.skip_security:
        findings.extend(check_security(params))

    if not opts.skip_debug:
        findings.extend(check_debug(params))

    if not opts.skip_performance:
        findings.extend(check_performance(params))

    # Sort by severity
    severity_order = {"CRITICAL": 0, "WARNING": 1, "INFO": 2}
    findings.sort(key=lambda x: (severity_order.get(x["severity"], 3), x["parameter"]))

    # Count by severity
    critical_count = sum(1 for f in findings if f["severity"] == "CRITICAL")
    warning_count = sum(1 for f in findings if f["severity"] == "WARNING")
    info_count = sum(1 for f in findings if f["severity"] == "INFO")

    # Build result
    result = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "cmdline": cmdline,
        "parameter_count": len(params),
        "parameters": params,
        "summary": {
            "critical": critical_count,
            "warning": warning_count,
            "info": info_count,
            "total": len(findings),
        },
        "findings": findings,
    }

    # Output handling
    if opts.format == "json":
        print(json.dumps(result, indent=2))
    else:
        if not opts.warn_only:
            lines = []
            lines.append("Kernel Command Line Audit")
            lines.append("=" * 70)
            lines.append("")

            if opts.verbose:
                lines.append(f"Full cmdline: {cmdline}")
                lines.append("")
                lines.append(f"Total parameters: {len(params)}")
                lines.append("")

        else:
            lines = []

        # Group findings by severity
        critical = [f for f in findings if f["severity"] == "CRITICAL"]
        warnings = [f for f in findings if f["severity"] == "WARNING"]
        info = [f for f in findings if f["severity"] == "INFO"]

        if critical:
            lines.append("CRITICAL ISSUES:")
            lines.append("-" * 70)
            for f in critical:
                value_str = f"={f['value']}" if f["value"] else ""
                lines.append(f"  !!! {f['parameter']}{value_str}")
                lines.append(f"      {f['description']}: {f['issue']}")
                if opts.verbose:
                    lines.append(f"      Recommendation: {f['recommendation']}")
            lines.append("")

        if warnings:
            lines.append("WARNINGS:")
            lines.append("-" * 70)
            for f in warnings:
                value_str = f"={f['value']}" if f["value"] else ""
                lines.append(f"  !   {f['parameter']}{value_str}")
                lines.append(f"      {f['description']}: {f['issue']}")
                if opts.verbose:
                    lines.append(f"      Recommendation: {f['recommendation']}")
            lines.append("")

        if info and not opts.warn_only:
            lines.append("INFORMATIONAL:")
            lines.append("-" * 70)
            for f in info:
                value_str = f"={f['value']}" if f["value"] else ""
                lines.append(f"  i   {f['parameter']}{value_str}")
                lines.append(f"      {f['description']}")
            lines.append("")

        if not opts.warn_only:
            lines.append("SUMMARY:")
            lines.append("-" * 70)
            lines.append(f"  Critical: {critical_count}")
            lines.append(f"  Warnings: {warning_count}")
            lines.append(f"  Info:     {info_count}")

        if not findings:
            lines.append("No issues detected.")

        print("\n".join(lines))

    # Store data for output helper
    output.emit(result)
    output.set_summary(f"critical={critical_count}, warnings={warning_count}")

    # Exit based on findings
    has_issues = critical_count > 0 or warning_count > 0
    return 1 if has_issues else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
