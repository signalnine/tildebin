#!/usr/bin/env python3
# boxctl:
#   category: baremetal/gpu
#   tags: [health, gpu, nvidia, cuda, ml]
#   requires: [nvidia-smi]
#   privilege: user
#   related: [thermal_zone, power_consumption]
#   brief: Monitor GPU health and performance using nvidia-smi

"""
Monitor GPU health and performance on baremetal systems.

Checks NVIDIA GPU health metrics including temperature, memory usage, ECC errors,
power consumption, and utilization using nvidia-smi. Essential for monitoring
GPU clusters in ML/AI workloads and detecting hardware issues before failures.

Returns exit code 1 if any GPU has warnings or critical conditions.
"""

import argparse
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def determine_gpu_status(gpu: dict[str, Any]) -> str:
    """Determine GPU health status based on metrics."""
    issues = []

    # Temperature checks
    temp = gpu.get('temperature')
    if temp is not None:
        if temp >= 90:
            return 'critical'
        elif temp >= 80:
            issues.append('high_temp')

    # ECC error checks
    ecc_uncorrected = gpu.get('ecc_uncorrected')
    ecc_corrected = gpu.get('ecc_corrected')

    if ecc_uncorrected is not None and ecc_uncorrected > 0:
        return 'critical'

    if ecc_corrected is not None and ecc_corrected > 100:
        issues.append('high_ecc')

    # Memory usage check (>95% is warning)
    mem_total = gpu.get('memory_total')
    mem_used = gpu.get('memory_used')
    if mem_total and mem_used:
        usage_pct = (mem_used / mem_total) * 100
        if usage_pct >= 95:
            issues.append('high_memory')

    # Power check (>95% of limit)
    power_draw = gpu.get('power_draw')
    power_limit = gpu.get('power_limit')
    if power_draw and power_limit and power_limit > 0:
        power_pct = (power_draw / power_limit) * 100
        if power_pct >= 95:
            issues.append('high_power')

    # Fan speed check (0 RPM when GPU is hot is bad)
    fan_speed = gpu.get('fan_speed')
    if fan_speed == 0 and temp and temp > 50:
        issues.append('fan_stopped')

    if issues:
        return 'warning'

    return 'healthy'


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
        description="Monitor GPU health and performance"
    )
    parser.add_argument(
        "--format",
        choices=["plain", "json"],
        default="plain"
    )
    parser.add_argument(
        "-w", "--warn-only",
        action="store_true",
        help="Only show GPUs with warnings or critical status"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed information"
    )

    opts = parser.parse_args(args)

    # Check if nvidia-smi is available
    if not context.check_tool("nvidia-smi"):
        output.error("nvidia-smi not found. NVIDIA drivers may not be installed.")

        output.render(opts.format, "Monitor GPU health and performance using nvidia-smi")
        return 2

    # Query format for detailed GPU information
    query_fields = [
        'index',
        'name',
        'uuid',
        'temperature.gpu',
        'temperature.memory',
        'utilization.gpu',
        'utilization.memory',
        'memory.total',
        'memory.used',
        'memory.free',
        'power.draw',
        'power.limit',
        'clocks.current.graphics',
        'clocks.current.memory',
        'ecc.errors.corrected.volatile.total',
        'ecc.errors.uncorrected.volatile.total',
        'pstate',
        'fan.speed',
    ]

    try:
        result = context.run([
            'nvidia-smi',
            '--query-gpu=' + ','.join(query_fields),
            '--format=csv,noheader,nounits'
        ], check=True)
    except Exception as e:
        output.error(f"Failed to run nvidia-smi: {e}")

        output.render(opts.format, "Monitor GPU health and performance using nvidia-smi")
        return 2

    gpus = []
    for line in result.stdout.strip().split('\n'):
        if not line:
            continue

        values = [v.strip() for v in line.split(', ')]
        if len(values) < len(query_fields):
            continue

        def parse_int(val):
            if val in ['[Not Supported]', '[N/A]', 'N/A', '']:
                return None
            try:
                return int(float(val))
            except (ValueError, TypeError):
                return None

        def parse_float(val):
            if val in ['[Not Supported]', '[N/A]', 'N/A', '']:
                return None
            try:
                return float(val)
            except (ValueError, TypeError):
                return None

        gpu = {
            'index': parse_int(values[0]),
            'name': values[1] if values[1] not in ['[Not Supported]', '[N/A]'] else 'Unknown',
            'uuid': values[2] if values[2] not in ['[Not Supported]', '[N/A]'] else None,
            'temperature': parse_int(values[3]),
            'temperature_memory': parse_int(values[4]),
            'utilization_gpu': parse_int(values[5]),
            'utilization_memory': parse_int(values[6]),
            'memory_total': parse_int(values[7]),
            'memory_used': parse_int(values[8]),
            'memory_free': parse_int(values[9]),
            'power_draw': parse_float(values[10]),
            'power_limit': parse_float(values[11]),
            'clock_graphics': parse_int(values[12]),
            'clock_memory': parse_int(values[13]),
            'ecc_corrected': parse_int(values[14]),
            'ecc_uncorrected': parse_int(values[15]),
            'pstate': values[16] if values[16] not in ['[Not Supported]', '[N/A]'] else None,
            'fan_speed': parse_int(values[17]),
        }

        gpu['status'] = determine_gpu_status(gpu)
        gpus.append(gpu)

    if not gpus:
        output.warning("No NVIDIA GPUs detected")
        output.emit({"gpus": []})

        output.render(opts.format, "Monitor GPU health and performance using nvidia-smi")
        return 0

    # Filter for warn-only mode
    filtered_gpus = gpus
    if opts.warn_only:
        filtered_gpus = [g for g in gpus if g['status'] != 'healthy']

    # Remove verbose fields if not requested
    if not opts.verbose:
        for gpu in filtered_gpus:
            gpu.pop('uuid', None)
            gpu.pop('temperature_memory', None)
            gpu.pop('clock_graphics', None)
            gpu.pop('clock_memory', None)
            gpu.pop('pstate', None)
            gpu.pop('ecc_corrected', None)
            gpu.pop('ecc_uncorrected', None)

    output.emit({"gpus": filtered_gpus})

    # Set summary
    healthy = sum(1 for g in gpus if g['status'] == 'healthy')
    warning = sum(1 for g in gpus if g['status'] == 'warning')
    critical = sum(1 for g in gpus if g['status'] == 'critical')
    output.set_summary(f"{healthy} healthy, {warning} warning, {critical} critical")

    # Return 1 if any issues
    has_issues = warning > 0 or critical > 0

    output.render(opts.format, "Monitor GPU health and performance using nvidia-smi")
    return 1 if has_issues else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
