# Baremetal Diagnostic Gaps Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add 18 missing baremetal diagnostic scripts covering IOMMU, eBPF, THP, fan monitoring, DMI inventory, PCI passthrough, ACPI events, KSM, RCU stalls, seccomp, Landlock, shared library audit, SMART trending, SAS link health, dm-integrity, LACP detailed health, XDP audit, and cgroup v1/v2 migration audit.

**Architecture:** Each script follows the existing boxctl pattern: YAML metadata in header comments, `run(args, output, context) -> int` entry point, MockContext-based tests. Scripts read from `/proc` and `/sys` virtual filesystems or invoke external tools via `context.run()`. Every script has a matching test file.

**Tech Stack:** Python 3, boxctl framework (Output, Context, MockContext), pytest

---

## Common Patterns Reference

All 18 scripts share identical structure. To avoid repetition, here is the template every script and test MUST follow:

### Script Template (`scripts/baremetal/<name>.py`)

```python
#!/usr/bin/env python3
# boxctl:
#   category: baremetal/<subcategory>
#   tags: [tag1, tag2]
#   requires: []          # or [tool-name] if external tool needed
#   privilege: user|root
#   related: [related_script1, related_script2]
#   brief: One-line description

"""
Multi-line docstring explaining what this monitors.

Exit codes:
    0 - Healthy
    1 - Issues found
    2 - Error or missing dependencies
"""

import argparse
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def parse_<something>(content: str) -> dict[str, Any]:
    """Parse function - pure, no I/O."""
    ...


def analyze_<something>(data: dict, ...) -> list[dict[str, Any]]:
    """Analyze data, return list of issue dicts with severity/type/message."""
    ...


def run(args: list[str], output: Output, context: Context) -> int:
    parser = argparse.ArgumentParser(description="...")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    parser.add_argument("-v", "--verbose", action="store_true")
    opts = parser.parse_args(args)

    # Check dependencies (files or tools)
    if not context.file_exists('/path'):
        output.error("...")
        output.render(opts.format, "Title")
        return 2

    # Read data via context
    content = context.read_file('/path')

    # Parse (pure functions)
    data = parse_<something>(content)

    # Analyze (pure functions)
    issues = analyze_<something>(data)

    # Emit structured data
    output.emit({'data': data, 'issues': issues})
    output.set_summary(f"...")
    output.render(opts.format, "Title")

    return 1 if any(i['severity'] != 'INFO' for i in issues) else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
```

### Test Template (`tests/scripts/baremetal/test_<name>.py`)

```python
"""Tests for <name> script."""

import json
import pytest

from boxctl.core.output import Output


class Test<Name>:
    """Tests for <name> script."""

    def test_missing_deps(self, mock_context):
        """Returns 2 when dependencies not available."""
        from scripts.baremetal.<name> import run
        ctx = mock_context(file_contents={})
        output = Output()
        assert run([], output, ctx) == 2

    def test_healthy(self, mock_context):
        """Returns 0 when healthy."""
        from scripts.baremetal.<name> import run
        ctx = mock_context(file_contents={...})  # healthy fixture data
        output = Output()
        assert run([], output, ctx) == 0

    def test_issues_detected(self, mock_context):
        """Returns 1 when issues found."""
        from scripts.baremetal.<name> import run
        ctx = mock_context(file_contents={...})  # problematic fixture data
        output = Output()
        assert run([], output, ctx) == 1

    def test_json_output(self, mock_context, capsys):
        """JSON output has expected fields."""
        from scripts.baremetal.<name> import run
        ctx = mock_context(file_contents={...})
        output = Output()
        run(["--format", "json"], output, ctx)
        assert '<expected_key>' in output.data
```

### Conventions

- **Exit codes:** 0=healthy, 1=issues, 2=error/missing deps
- **Severity levels:** CRITICAL, WARNING, INFO
- **Issue dict:** `{'severity': str, 'type': str, 'message': str, ...}`
- **All I/O through Context:** `context.read_file()`, `context.file_exists()`, `context.glob()`, `context.check_tool()`, `context.run()`
- **Test with MockContext:** `mock_context(file_contents={path: content})` or `mock_context(tools_available=[...], command_outputs={...})`
- **No real I/O in tests** - everything mocked via MockContext

---

## Task 1: IOMMU/DMA Remapping Status

**Files:**
- Create: `scripts/baremetal/iommu_status.py`
- Test: `tests/scripts/baremetal/test_iommu_status.py`

**What it checks:**
- Whether IOMMU (Intel VT-d / AMD-Vi) is enabled via `/sys/class/iommu/`
- IOMMU groups from `/sys/kernel/iommu_groups/`
- Kernel cmdline for `intel_iommu=on`, `amd_iommu=on`, `iommu=pt` via `/proc/cmdline`
- DMAR table presence via `context.file_exists('/sys/firmware/acpi/tables/DMAR')`

**Data sources:**
- `/sys/class/iommu/` - directory listing (glob `*`)
- `/sys/kernel/iommu_groups/*/devices/*` - glob for device assignments
- `/proc/cmdline` - kernel parameters
- `/sys/firmware/acpi/tables/DMAR` or `/sys/firmware/acpi/tables/IVRS` - ACPI tables

**Metadata:**
```yaml
category: baremetal/security
tags: [security, iommu, vt-d, amd-vi, virtualization, dma]
requires: []
privilege: root
related: [pcie_health, kernel_cmdline_audit]
brief: Audit IOMMU/DMA remapping configuration and device isolation
```

**Issues to detect:**
- IOMMU hardware present (DMAR/IVRS table) but not enabled in kernel → CRITICAL
- IOMMU enabled but not in passthrough mode when expected → WARNING
- IOMMU groups with mixed device types (potential isolation concern) → INFO
- No IOMMU hardware detected → INFO

**Tests:**
1. `test_no_iommu_hardware` - no DMAR/IVRS tables, no `/sys/class/iommu/` → exit 0 with INFO
2. `test_iommu_enabled_healthy` - DMAR exists, iommu dir populated, cmdline has `intel_iommu=on` → exit 0
3. `test_iommu_hardware_not_enabled` - DMAR exists but `/sys/class/iommu/` empty, cmdline lacks `intel_iommu=on` → exit 1 CRITICAL
4. `test_iommu_groups_enumerated` - groups with devices listed in output data
5. `test_missing_deps` - no files available → exit 2

---

## Task 2: Fan Speed Monitoring

**Files:**
- Create: `scripts/baremetal/fan_speed.py`
- Test: `tests/scripts/baremetal/test_fan_speed.py`

**What it checks:**
- Fan RPM from `/sys/class/hwmon/hwmon*/fan*_input`
- Fan min/max from `fan*_min`, `fan*_max`
- Fan labels from `fan*_label`
- IPMI fan data if `ipmitool` available (fallback)

**Data sources:**
- `/sys/class/hwmon/hwmon*/name` - sensor chip name
- `/sys/class/hwmon/hwmon*/fan*_input` - current RPM
- `/sys/class/hwmon/hwmon*/fan*_min` - minimum RPM threshold
- `/sys/class/hwmon/hwmon*/fan*_label` - fan label

**Metadata:**
```yaml
category: baremetal/hardware
tags: [hardware, fan, cooling, thermal, health]
requires: []
privilege: user
related: [hardware_temperature, thermal_throttle, psu_monitor]
brief: Monitor fan speeds and detect cooling failures
```

**Issues to detect:**
- Fan RPM = 0 when other fans are spinning → CRITICAL (fan failure)
- Fan RPM below minimum threshold → WARNING
- No fan sensors detected → INFO (may be passively cooled or virtual)

**Tests:**
1. `test_no_fan_sensors` - no hwmon fan files → exit 0 with INFO
2. `test_all_fans_healthy` - all fans above min → exit 0
3. `test_fan_stopped` - one fan at 0 RPM while others spin → exit 1 CRITICAL
4. `test_fan_below_min` - fan below min threshold → exit 1 WARNING
5. `test_missing_deps` - no `/sys/class/hwmon` → exit 2

---

## Task 3: DMI/SMBIOS Hardware Inventory

**Files:**
- Create: `scripts/baremetal/dmi_inventory.py`
- Test: `tests/scripts/baremetal/test_dmi_inventory.py`

**What it checks:**
- System manufacturer, product, serial from `/sys/class/dmi/id/`
- BIOS vendor, version, date from `/sys/class/dmi/id/bios_*`
- Board info from `/sys/class/dmi/id/board_*`
- Chassis type from `/sys/class/dmi/id/chassis_type`

**Data sources:**
- `/sys/class/dmi/id/sys_vendor`
- `/sys/class/dmi/id/product_name`
- `/sys/class/dmi/id/product_serial`
- `/sys/class/dmi/id/bios_vendor`
- `/sys/class/dmi/id/bios_version`
- `/sys/class/dmi/id/bios_date`
- `/sys/class/dmi/id/board_vendor`
- `/sys/class/dmi/id/board_name`
- `/sys/class/dmi/id/chassis_type`

**Metadata:**
```yaml
category: baremetal/hardware
tags: [hardware, inventory, dmi, smbios, bios, asset]
requires: []
privilege: user
related: [firmware_inventory, firmware_version_audit]
brief: Report DMI/SMBIOS hardware inventory and asset information
```

**Issues to detect:**
- BIOS date older than 3 years → WARNING (may need firmware update)
- Unknown/empty vendor strings → INFO

**Tests:**
1. `test_no_dmi_dir` - no `/sys/class/dmi/id/` → exit 2
2. `test_full_inventory` - all fields present → exit 0, data has all fields
3. `test_old_bios_date` - bios_date is 2020 → exit 1 WARNING
4. `test_partial_data` - some fields missing → exit 0, missing fields are null
5. `test_json_output` - verify JSON structure

---

## Task 4: PCI Passthrough Audit

**Files:**
- Create: `scripts/baremetal/pci_passthrough_audit.py`
- Test: `tests/scripts/baremetal/test_pci_passthrough_audit.py`

**What it checks:**
- Devices bound to VFIO driver via `/sys/bus/pci/drivers/vfio-pci/`
- IOMMU group isolation for passthrough devices
- Driver binding status for devices in IOMMU groups

**Data sources:**
- `/sys/bus/pci/drivers/vfio-pci/` - glob for bound devices (symlinks)
- `/sys/bus/pci/devices/*/driver` - readlink to check current driver
- `/sys/kernel/iommu_groups/*/devices/*` - group membership
- `/sys/bus/pci/devices/*/class` - PCI class code
- `/sys/bus/pci/devices/*/vendor`, `device` - PCI IDs

**Metadata:**
```yaml
category: baremetal/virtualization
tags: [virtualization, pci, passthrough, vfio, iommu, gpu]
requires: []
privilege: root
related: [iommu_status, pcie_health, gpu_health]
brief: Audit PCI device passthrough configuration and VFIO bindings
```

**Issues to detect:**
- VFIO-bound device in group with non-VFIO devices → WARNING (isolation concern)
- VFIO module not loaded but passthrough devices configured → CRITICAL
- No passthrough devices configured → INFO (inventory only)

**Tests:**
1. `test_no_vfio_devices` - no vfio-pci driver dir → exit 0 INFO
2. `test_healthy_passthrough` - device bound to vfio, isolated group → exit 0
3. `test_mixed_group` - vfio device sharing group with host device → exit 1 WARNING
4. `test_missing_deps` - no PCI sysfs → exit 2

---

## Task 5: ACPI Event Monitoring

**Files:**
- Create: `scripts/baremetal/acpi_events.py`
- Test: `tests/scripts/baremetal/test_acpi_events.py`

**What it checks:**
- Thermal trip points from `/sys/class/thermal/thermal_zone*/trip_point_*_temp`
- Whether any thermal zone is near trip point
- ACPI error messages in dmesg via `context.run(['dmesg'])` filtered for ACPI
- Power supply status from `/sys/class/power_supply/*/status`

**Data sources:**
- `/sys/class/thermal/thermal_zone*/temp` - current temp
- `/sys/class/thermal/thermal_zone*/trip_point_*_temp` - trip points
- `/sys/class/thermal/thermal_zone*/trip_point_*_type` - trip type (critical, hot, passive)
- `/sys/class/power_supply/*/status` - Charging/Discharging/Not charging
- dmesg output filtered for ACPI errors

**Metadata:**
```yaml
category: baremetal/hardware
tags: [hardware, acpi, thermal, power, events]
requires: []
privilege: root
related: [thermal_zone, thermal_throttle, hardware_temperature]
brief: Monitor ACPI thermal trip points, power events, and error conditions
```

**Issues to detect:**
- Temperature within 10C of critical trip point → CRITICAL
- Temperature within 20C of hot/passive trip point → WARNING
- ACPI errors in dmesg → WARNING
- No thermal zones found → INFO

**Tests:**
1. `test_no_thermal_zones` - no thermal zone dirs → exit 0 INFO
2. `test_healthy_temps` - temps well below trip points → exit 0
3. `test_near_critical_trip` - temp within 10C of critical → exit 1 CRITICAL
4. `test_acpi_dmesg_errors` - dmesg contains ACPI errors → exit 1 WARNING
5. `test_missing_deps` - no sysfs → exit 2

---

## Task 6: eBPF Program Audit

**Files:**
- Create: `scripts/baremetal/ebpf_audit.py`
- Test: `tests/scripts/baremetal/test_ebpf_audit.py`

**What it checks:**
- Loaded BPF programs via `bpftool prog list --json`
- BPF maps via `bpftool map list --json`
- Program types, attach points, and memory usage

**Data sources:**
- `bpftool prog list --json` - list all loaded BPF programs
- `bpftool map list --json` - list all BPF maps

**Metadata:**
```yaml
category: baremetal/security
tags: [security, ebpf, bpf, kernel, audit]
requires: [bpftool]
privilege: root
related: [kernel_module_audit, security_modules]
brief: Audit loaded eBPF programs and maps for security review
```

**Issues to detect:**
- Programs of type `tracing`/`kprobe`/`raw_tracepoint` from unknown sources → WARNING
- Very large number of BPF programs (>100) → WARNING (potential leak)
- BPF maps consuming excessive memory → WARNING
- No bpftool available → exit 2

**Tests:**
1. `test_bpftool_missing` - tool not available → exit 2
2. `test_no_programs` - empty JSON array → exit 0
3. `test_healthy_programs` - few well-known programs → exit 0
4. `test_excessive_programs` - >100 programs → exit 1 WARNING
5. `test_json_output` - verify program list in output data

---

## Task 7: XDP Program Audit

**Files:**
- Create: `scripts/baremetal/xdp_audit.py`
- Test: `tests/scripts/baremetal/test_xdp_audit.py`

**What it checks:**
- XDP programs attached to network interfaces via `ip -j link show`
- XDP mode (native, generic, offloaded)
- Which interfaces have XDP programs

**Data sources:**
- `ip -j link show` - JSON output of all network interfaces with XDP info
- Parses `xdp` field in link JSON for program IDs and mode

**Metadata:**
```yaml
category: baremetal/network
tags: [network, xdp, ebpf, performance, security]
requires: [ip]
privilege: root
related: [ebpf_audit, ethtool_audit, nic_link_speed]
brief: Audit XDP programs attached to network interfaces
```

**Issues to detect:**
- XDP in generic mode (poor performance vs native) → WARNING
- XDP on bonding/bridge members (potential conflicts) → WARNING
- No XDP programs found → INFO (inventory only)

**Tests:**
1. `test_ip_missing` - tool not available → exit 2
2. `test_no_xdp` - interfaces with no XDP → exit 0 INFO
3. `test_native_xdp` - interface with native XDP → exit 0
4. `test_generic_xdp` - interface with generic mode → exit 1 WARNING
5. `test_json_output` - verify interface XDP data

---

## Task 8: KSM (Kernel Samepage Merging) Monitor

**Files:**
- Create: `scripts/baremetal/ksm_monitor.py`
- Test: `tests/scripts/baremetal/test_ksm_monitor.py`

**What it checks:**
- KSM status from `/sys/kernel/mm/ksm/run` (0=stopped, 1=running, 2=unloading)
- Pages shared/sharing/unshared from `/sys/kernel/mm/ksm/pages_*`
- Full scans completed from `/sys/kernel/mm/ksm/full_scans`
- Sleep interval from `/sys/kernel/mm/ksm/sleep_millisecs`

**Data sources:**
- `/sys/kernel/mm/ksm/run`
- `/sys/kernel/mm/ksm/pages_shared`
- `/sys/kernel/mm/ksm/pages_sharing`
- `/sys/kernel/mm/ksm/pages_unshared`
- `/sys/kernel/mm/ksm/pages_volatile`
- `/sys/kernel/mm/ksm/full_scans`
- `/sys/kernel/mm/ksm/sleep_millisecs`

**Metadata:**
```yaml
category: baremetal/memory
tags: [memory, ksm, deduplication, virtualization, performance]
requires: []
privilege: user
related: [memory_usage, hugepage_monitor, libvirt_health]
brief: Monitor Kernel Samepage Merging status and efficiency
```

**Issues to detect:**
- KSM running but sharing ratio very low (<1%) → WARNING (wasting CPU for little benefit)
- KSM not running on a VM host (libvirt detected) → INFO
- Very high unshared page count relative to shared → WARNING (inefficient scanning)

**Tests:**
1. `test_ksm_not_available` - no `/sys/kernel/mm/ksm/run` → exit 2
2. `test_ksm_stopped` - run=0 → exit 0 INFO
3. `test_ksm_healthy` - run=1, good sharing ratio → exit 0
4. `test_ksm_low_efficiency` - run=1, minimal sharing → exit 1 WARNING
5. `test_json_output` - verify all KSM metrics in output

---

## Task 9: THP (Transparent Huge Pages) Compaction Monitor

**Files:**
- Create: `scripts/baremetal/thp_monitor.py`
- Test: `tests/scripts/baremetal/test_thp_monitor.py`

**What it checks:**
- THP enabled/defrag settings from `/sys/kernel/mm/transparent_hugepage/`
- Compaction stalls and failures from `/proc/vmstat` (compact_stall, compact_fail, compact_success)
- THP allocation failures from `/proc/vmstat` (thp_fault_alloc, thp_fault_fallback, thp_collapse_alloc, thp_collapse_alloc_failed)
- khugepaged scan status from `/sys/kernel/mm/transparent_hugepage/khugepaged/`

**Data sources:**
- `/sys/kernel/mm/transparent_hugepage/enabled`
- `/sys/kernel/mm/transparent_hugepage/defrag`
- `/sys/kernel/mm/transparent_hugepage/khugepaged/pages_to_scan`
- `/sys/kernel/mm/transparent_hugepage/khugepaged/scan_sleep_millisecs`
- `/proc/vmstat` - filtered for `thp_`, `compact_` keys

**Metadata:**
```yaml
category: baremetal/memory
tags: [memory, thp, hugepages, compaction, performance]
requires: []
privilege: user
related: [hugepage_monitor, memory_fragmentation, memory_reclaim_monitor]
brief: Monitor THP compaction stalls and allocation efficiency
```

**Issues to detect:**
- THP set to `always` with high compaction stall count → WARNING
- thp_fault_fallback significantly higher than thp_fault_alloc → WARNING (fragmentation)
- thp_collapse_alloc_failed high → WARNING (khugepaged struggling)
- THP `defrag` set to `always` (can cause latency spikes) → INFO

**Tests:**
1. `test_no_thp_support` - no transparent_hugepage dir → exit 2
2. `test_thp_healthy` - low fallback ratio, low stalls → exit 0
3. `test_high_compaction_stalls` - compact_stall high → exit 1 WARNING
4. `test_high_fallback_ratio` - fallback >> alloc → exit 1 WARNING
5. `test_thp_disabled` - enabled=never → exit 0 INFO

---

## Task 10: RCU Stall Detection

**Files:**
- Create: `scripts/baremetal/rcu_stall_detector.py`
- Test: `tests/scripts/baremetal/test_rcu_stall_detector.py`

**What it checks:**
- RCU stall warnings in dmesg output
- RCU callback statistics from `/sys/kernel/debug/rcu/rcu_preempt/rcudata` (if available)
- RCU expedited grace periods from `/proc/sys/kernel/rcu_expedited`

**Data sources:**
- `dmesg` output - filtered for "RCU" stall patterns
- `/sys/kernel/debug/rcu/` - RCU debug files (optional, needs debugfs)
- `/proc/sys/kernel/rcu_expedited` - expedited mode status

**Metadata:**
```yaml
category: baremetal/kernel
tags: [kernel, rcu, stall, stability, latency]
requires: []
privilege: root
related: [kernel_lockup_detector, softlockup, dmesg_analyzer]
brief: Detect RCU stall warnings indicating kernel scheduling issues
```

**Issues to detect:**
- "rcu_sched self-detected stall" or "rcu_preempt self-detected stall" in dmesg → CRITICAL
- "rcu_sched kthread starved" in dmesg → WARNING
- RCU expedited mode enabled permanently → INFO (higher CPU overhead)

**Tests:**
1. `test_dmesg_unavailable` - dmesg fails → exit 2
2. `test_no_stalls` - clean dmesg, no RCU issues → exit 0
3. `test_rcu_stall_detected` - dmesg contains stall warning → exit 1 CRITICAL
4. `test_rcu_kthread_starved` - dmesg contains starvation → exit 1 WARNING
5. `test_expedited_mode` - rcu_expedited=1 → exit 0 with INFO note

---

## Task 11: seccomp Filter Audit

**Files:**
- Create: `scripts/baremetal/seccomp_audit.py`
- Test: `tests/scripts/baremetal/test_seccomp_audit.py`

**What it checks:**
- Per-process seccomp mode from `/proc/[pid]/status` (Seccomp field)
- Seccomp modes: 0=disabled, 1=strict, 2=filter
- Summary of processes with/without seccomp

**Data sources:**
- `/proc/[pid]/status` - Seccomp field
- `/proc/[pid]/comm` - process name

**Metadata:**
```yaml
category: baremetal/security
tags: [security, seccomp, sandbox, process, audit]
requires: []
privilege: root
related: [process_capabilities_auditor, security_modules, namespace_audit]
brief: Audit seccomp filter status across running processes
```

**Issues to detect:**
- Critical system daemons (sshd, systemd services) running without seccomp → WARNING
- High percentage of processes without any seccomp filtering → INFO
- Summary stats: total processes, filtered vs unfiltered

**Tests:**
1. `test_no_proc` - no `/proc` → exit 2
2. `test_all_filtered` - all processes have seccomp=2 → exit 0
3. `test_mixed_filtering` - some with, some without → exit 0 (with summary)
4. `test_json_output` - verify process list and summary stats

---

## Task 12: Landlock/io_uring Restriction Audit

**Files:**
- Create: `scripts/baremetal/lsm_restriction_audit.py`
- Test: `tests/scripts/baremetal/test_lsm_restriction_audit.py`

**What it checks:**
- Landlock ABI version from `/sys/kernel/security/lsm`
- Landlock filesystem support
- io_uring restrictions from `/proc/sys/kernel/io_uring_disabled`
- Active LSM list

**Data sources:**
- `/sys/kernel/security/lsm` - comma-separated LSM list
- `/proc/sys/kernel/io_uring_disabled` - io_uring restriction level (0=allowed, 1=unprivileged disabled, 2=all disabled)
- `/proc/sys/kernel/io_uring_group` - allowed group (if restricted)

**Metadata:**
```yaml
category: baremetal/security
tags: [security, landlock, io_uring, lsm, sandbox, kernel]
requires: []
privilege: user
related: [security_modules, kernel_hardening_audit, seccomp_audit]
brief: Audit Landlock LSM and io_uring restriction configuration
```

**Issues to detect:**
- Landlock not in LSM list on kernel 5.13+ → WARNING (should be enabled)
- io_uring unrestricted (disabled=0) on production systems → WARNING
- io_uring fully disabled on systems that need it → INFO

**Tests:**
1. `test_no_lsm_file` - no `/sys/kernel/security/lsm` → exit 2
2. `test_landlock_enabled` - lsm list includes "landlock" → exit 0
3. `test_landlock_missing` - lsm list without "landlock" → exit 1 WARNING
4. `test_io_uring_unrestricted` - disabled=0 → exit 1 WARNING
5. `test_io_uring_disabled` - disabled=2 → exit 0

---

## Task 13: Shared Library Audit

**Files:**
- Create: `scripts/baremetal/shared_library_audit.py`
- Test: `tests/scripts/baremetal/test_shared_library_audit.py`

**What it checks:**
- LD_PRELOAD set in environment or `/etc/ld.so.preload`
- Suspicious entries in `/etc/ld.so.conf.d/`
- World-writable library directories
- `/etc/ld.so.preload` contents

**Data sources:**
- `/etc/ld.so.preload` - preloaded libraries
- `/etc/ld.so.conf` - library search paths
- `/etc/ld.so.conf.d/` - additional config files (glob `*.conf`)
- Check permissions on standard lib dirs via context

**Metadata:**
```yaml
category: baremetal/security
tags: [security, libraries, ld_preload, audit, integrity]
requires: []
privilege: root
related: [suid_sgid_audit, file_integrity, kernel_module_audit]
brief: Audit shared library configuration for hijacking risks
```

**Issues to detect:**
- `/etc/ld.so.preload` exists with entries → WARNING (potential LD_PRELOAD hijacking)
- Non-standard paths in ld.so.conf → INFO
- Library config pointing to world-writable directories → CRITICAL

**Tests:**
1. `test_no_preload_clean` - no preload file, standard conf → exit 0
2. `test_preload_exists` - `/etc/ld.so.preload` has entries → exit 1 WARNING
3. `test_clean_config` - standard library paths only → exit 0
4. `test_json_output` - verify library path listing

---

## Task 14: SMART Trend Analysis

**Files:**
- Create: `scripts/baremetal/smart_trend.py`
- Test: `tests/scripts/baremetal/test_smart_trend.py`

**What it checks:**
- SMART attributes from `smartctl -A /dev/sdX --json`
- Rate of change for critical attributes: Reallocated_Sector_Ct, Current_Pending_Sector, Offline_Uncorrectable
- Compares RAW_VALUE against THRESH
- Checks if WORST is declining toward THRESH

**Data sources:**
- `smartctl --scan --json` - list all drives
- `smartctl -A /dev/sdX --json` - SMART attributes per drive

**Metadata:**
```yaml
category: baremetal/storage
tags: [storage, smart, disk, health, trend, prediction]
requires: [smartctl]
privilege: root
related: [disk_health, disk_life_predictor, ssd_wear, nvme_health]
brief: Analyze SMART attribute trends for early disk failure detection
```

**Issues to detect:**
- Reallocated_Sector_Ct raw value > 0 → WARNING
- Reallocated_Sector_Ct raw value > 100 → CRITICAL
- Current_Pending_Sector > 0 → WARNING
- Offline_Uncorrectable > 0 → CRITICAL
- Any attribute VALUE approaching THRESH (within 10%) → WARNING

**Tests:**
1. `test_smartctl_missing` - tool not available → exit 2
2. `test_no_drives` - scan returns empty → exit 0
3. `test_healthy_drives` - all attributes well above threshold → exit 0
4. `test_reallocated_sectors` - Reallocated_Sector_Ct > 0 → exit 1 WARNING
5. `test_critical_sectors` - Reallocated_Sector_Ct > 100 → exit 1 CRITICAL
6. `test_attribute_near_threshold` - VALUE near THRESH → exit 1 WARNING

---

## Task 15: SAS/SCSI Link Health

**Files:**
- Create: `scripts/baremetal/sas_link_health.py`
- Test: `tests/scripts/baremetal/test_sas_link_health.py`

**What it checks:**
- SAS link speed from `/sys/class/sas_phy/*/negotiated_linkrate`
- Maximum link rate from `/sys/class/sas_phy/*/maximum_linkrate`
- Invalid DWORD count and other error counters from sysfs
- Speed downgrade detection (negotiated < maximum)

**Data sources:**
- `/sys/class/sas_phy/` - glob for SAS PHY devices
- `/sys/class/sas_phy/*/negotiated_linkrate` - current speed
- `/sys/class/sas_phy/*/maximum_linkrate` - max capable speed
- `/sys/class/sas_phy/*/invalid_dword_count` - error counter
- `/sys/class/sas_phy/*/loss_of_dword_sync_count` - sync loss counter
- `/sys/class/sas_phy/*/running_disparity_error_count` - disparity errors
- `/sys/class/sas_phy/*/phy_reset_problem_count` - reset issues

**Metadata:**
```yaml
category: baremetal/storage
tags: [storage, sas, scsi, link, health, performance]
requires: []
privilege: user
related: [scsi_error_monitor, disk_health, multipath_health]
brief: Monitor SAS/SCSI link speeds and detect link degradation
```

**Issues to detect:**
- negotiated_linkrate < maximum_linkrate → WARNING (speed downgrade)
- invalid_dword_count > 0 → WARNING (link errors)
- loss_of_dword_sync_count > 0 → WARNING
- running_disparity_error_count > 0 → WARNING
- No SAS PHYs found → INFO

**Tests:**
1. `test_no_sas_phys` - no `/sys/class/sas_phy/` → exit 0 INFO
2. `test_healthy_links` - negotiated = maximum, no errors → exit 0
3. `test_speed_downgrade` - negotiated < maximum → exit 1 WARNING
4. `test_link_errors` - non-zero error counters → exit 1 WARNING
5. `test_missing_deps` - sysfs not available → exit 2

---

## Task 16: dm-integrity/dm-verity Status

**Files:**
- Create: `scripts/baremetal/dm_integrity.py`
- Test: `tests/scripts/baremetal/test_dm_integrity.py`

**What it checks:**
- dm-integrity and dm-verity devices from `dmsetup table` output
- Target type detection (integrity, verity)
- Verity corruption status from `dmsetup status`

**Data sources:**
- `dmsetup table --target integrity` - list integrity targets
- `dmsetup table --target verity` - list verity targets
- `dmsetup status` - device status including error counts

**Metadata:**
```yaml
category: baremetal/storage
tags: [storage, dm-integrity, dm-verity, integrity, security]
requires: [dmsetup]
privilege: root
related: [disk_encryption, file_integrity, lvm_health]
brief: Monitor dm-integrity and dm-verity device status
```

**Issues to detect:**
- Verity device in corrupted state → CRITICAL
- Integrity device with mismatches detected → CRITICAL
- No integrity/verity devices found → INFO (inventory only)

**Tests:**
1. `test_dmsetup_missing` - tool not available → exit 2
2. `test_no_dm_devices` - no integrity/verity targets → exit 0 INFO
3. `test_healthy_verity` - verity device with clean status → exit 0
4. `test_corrupted_verity` - verity shows corruption → exit 1 CRITICAL
5. `test_json_output` - verify device list in output

---

## Task 17: LACP Detailed Health

**Files:**
- Create: `scripts/baremetal/lacp_health.py`
- Test: `tests/scripts/baremetal/test_lacp_health.py`

**What it checks:**
- LACP partner info from `/proc/net/bonding/*`
- LACP rate (fast/slow)
- Partner system MAC and key consistency across slaves
- MII status per slave
- LACP PDU counters (if available)

**Data sources:**
- `/proc/net/bonding/*` - glob for bond interfaces
- Parses: Partner Mac Address, LACP rate, Aggregator ID, Actor/Partner info

**Metadata:**
```yaml
category: baremetal/network
tags: [network, lacp, bonding, link-aggregation, health]
requires: []
privilege: user
related: [bond_health_monitor, nic_link_speed, link_flap]
brief: Detailed LACP bond health including partner and PDU analysis
```

**Issues to detect:**
- Different Partner Mac across slaves → CRITICAL (misconfigured switch LAG)
- Different Aggregator IDs across slaves → WARNING (split aggregation)
- Slave with MII Status: down → CRITICAL
- LACP rate mismatch expectations → INFO
- No bond interfaces found → INFO

**Tests:**
1. `test_no_bond_interfaces` - no `/proc/net/bonding/` files → exit 0 INFO
2. `test_healthy_lacp` - consistent partner, all slaves up → exit 0
3. `test_partner_mac_mismatch` - different partner MACs → exit 1 CRITICAL
4. `test_slave_down` - one slave MII Status: down → exit 1 CRITICAL
5. `test_split_aggregation` - different Aggregator IDs → exit 1 WARNING
6. `test_non_lacp_bond` - mode is not 802.3ad → exit 0 INFO (skip LACP checks)

---

## Task 18: cgroup v1/v2 Migration Audit

**Files:**
- Create: `scripts/baremetal/cgroup_version_audit.py`
- Test: `tests/scripts/baremetal/test_cgroup_version_audit.py`

**What it checks:**
- Whether cgroup v2 (unified) is mounted from `/proc/mounts` or `/sys/fs/cgroup/cgroup.controllers`
- cgroup v1 hierarchies still active from `/proc/cgroups`
- Hybrid mode detection (both v1 and v2 active)
- Controller availability per version

**Data sources:**
- `/proc/mounts` - check for `cgroup2` filesystem type
- `/proc/cgroups` - v1 controller listing (hierarchy, num_cgroups, enabled)
- `/sys/fs/cgroup/cgroup.controllers` - v2 available controllers
- `/sys/fs/cgroup/cgroup.subtree_control` - v2 active controllers

**Metadata:**
```yaml
category: baremetal/kernel
tags: [kernel, cgroup, v1, v2, migration, containers]
requires: []
privilege: user
related: [cgroup_cpu_limits, cgroup_memory_limits, cgroup_pressure, container_runtime_health]
brief: Audit cgroup v1 vs v2 configuration and detect hybrid mode
```

**Issues to detect:**
- Hybrid mode (both v1 and v2 active) → WARNING (can cause confusion)
- Still on cgroup v1 only (no v2) → INFO (migration recommended)
- Controllers on v1 that should be on v2 → INFO
- Clean v2 unified hierarchy → healthy

**Tests:**
1. `test_no_cgroup_info` - no proc files → exit 2
2. `test_pure_v2` - cgroup2 mounted, no v1 → exit 0
3. `test_hybrid_mode` - both v1 and v2 → exit 1 WARNING
4. `test_v1_only` - cgroup v1 only → exit 0 with INFO
5. `test_json_output` - verify controller listing per version

---

## Execution Sequence

Tasks 1-18 are fully independent - they share no code dependencies and can all be implemented in parallel. Each task is: write script → write test → run test → verify pass.

**Recommended parallel batches for subagent execution:**
- Batch 1 (sysfs readers): Tasks 1, 2, 3, 4, 8, 9, 15
- Batch 2 (mixed sources): Tasks 5, 10, 11, 17, 18
- Batch 3 (external tools): Tasks 6, 7, 14, 16
- Batch 4 (security audits): Tasks 12, 13

After all tasks complete:
1. Run full test suite: `python3 -m pytest tests/scripts/baremetal/ -v --tb=short`
2. Verify all 18 new test files pass
3. Commit and push
