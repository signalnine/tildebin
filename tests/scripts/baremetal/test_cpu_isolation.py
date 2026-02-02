"""Tests for cpu_isolation script."""

import pytest

from boxctl.core.output import Output


PROC_INTERRUPTS = """           CPU0       CPU1       CPU2       CPU3
  0:         20          0          0          0   IO-APIC   timer
  1:          2          0          0          0   IO-APIC   i8042
  8:          0          0          0          0   IO-APIC   rtc0
 18:       1234       5678          0          0   IO-APIC   eth0
"""


class TestCpuIsolation:
    """Tests for cpu_isolation script."""

    def test_no_online_cpus(self, mock_context):
        """Returns exit code 2 when cannot determine online CPUs."""
        from scripts.baremetal import cpu_isolation

        ctx = mock_context(
            tools_available=["ls"],
            file_contents={},
        )
        output = Output()

        exit_code = cpu_isolation.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0

    def test_no_isolation_configured(self, mock_context):
        """Returns 0 when no CPU isolation configured."""
        from scripts.baremetal import cpu_isolation

        ctx = mock_context(
            tools_available=["ls"],
            file_contents={
                "/sys/devices/system/cpu/online": "0-7",
                "/proc/cmdline": "BOOT_IMAGE=/vmlinuz root=/dev/sda1",
            }
        )
        output = Output()

        exit_code = cpu_isolation.run([], output, ctx)

        assert exit_code == 0
        assert output.data["status"] == "none"
        assert output.data["cpu_count"] == 8

    def test_full_isolation_configured(self, mock_context):
        """Returns 0 when full isolation is properly configured."""
        from scripts.baremetal import cpu_isolation

        ctx = mock_context(
            tools_available=["ls"],
            command_outputs={
                ("ls", "/proc/irq"): "0\n1\n8\n18\n",
            },
            file_contents={
                "/sys/devices/system/cpu/online": "0-7",
                "/proc/cmdline": "isolcpus=2-5 nohz_full=2-5 rcu_nocbs=2-5",
                "/proc/interrupts": PROC_INTERRUPTS,
                "/proc/irq/0/smp_affinity_list": "0-1,6-7",
                "/proc/irq/1/smp_affinity_list": "0-1,6-7",
                "/proc/irq/8/smp_affinity_list": "0-1,6-7",
                "/proc/irq/18/smp_affinity_list": "0-1,6-7",
            }
        )
        output = Output()

        exit_code = cpu_isolation.run([], output, ctx)

        assert exit_code == 0
        assert output.data["status"] == "ok"
        assert output.data["isolation"]["isolcpus"] == [2, 3, 4, 5]
        assert output.data["isolation"]["nohz_full"] == [2, 3, 4, 5]
        assert output.data["isolation"]["rcu_nocbs"] == [2, 3, 4, 5]

    def test_inconsistent_isolation(self, mock_context):
        """Returns 1 when isolation parameters are inconsistent."""
        from scripts.baremetal import cpu_isolation

        ctx = mock_context(
            tools_available=["ls"],
            command_outputs={
                ("ls", "/proc/irq"): "",
            },
            file_contents={
                "/sys/devices/system/cpu/online": "0-7",
                "/proc/cmdline": "isolcpus=2-5 nohz_full=2-4 rcu_nocbs=2-3",
            }
        )
        output = Output()

        exit_code = cpu_isolation.run([], output, ctx)

        assert exit_code == 1
        assert len(output.data["warnings"]) > 0
        # Should warn about inconsistency
        assert any("inconsistent" in w.lower() or "missing" in w.lower()
                  for w in output.data["warnings"])

    def test_irq_on_isolated_cpu(self, mock_context):
        """Returns 1 when IRQ can fire on isolated CPU."""
        from scripts.baremetal import cpu_isolation

        ctx = mock_context(
            tools_available=["ls"],
            command_outputs={
                ("ls", "/proc/irq"): "0\n18\n",
            },
            file_contents={
                "/sys/devices/system/cpu/online": "0-7",
                "/proc/cmdline": "isolcpus=2-5 nohz_full=2-5 rcu_nocbs=2-5",
                "/proc/interrupts": PROC_INTERRUPTS,
                "/proc/irq/0/smp_affinity_list": "0-1",
                "/proc/irq/18/smp_affinity_list": "0-3",  # Overlaps with isolated CPUs!
            }
        )
        output = Output()

        exit_code = cpu_isolation.run([], output, ctx)

        assert exit_code == 1
        assert len(output.data["issues"]) > 0
        # Should have issue about IRQ
        assert any("irq" in i.lower() for i in output.data["issues"])

    def test_cpu_0_isolated_warning(self, mock_context):
        """Warns when CPU 0 is isolated."""
        from scripts.baremetal import cpu_isolation

        ctx = mock_context(
            tools_available=["ls"],
            command_outputs={
                ("ls", "/proc/irq"): "",
            },
            file_contents={
                "/sys/devices/system/cpu/online": "0-7",
                "/proc/cmdline": "isolcpus=0-3 nohz_full=0-3 rcu_nocbs=0-3",
            }
        )
        output = Output()

        exit_code = cpu_isolation.run([], output, ctx)

        assert exit_code == 1
        assert any("cpu 0" in w.lower() for w in output.data["warnings"])

    def test_verbose_includes_details(self, mock_context):
        """--verbose includes additional details."""
        from scripts.baremetal import cpu_isolation

        ctx = mock_context(
            tools_available=["ls"],
            command_outputs={
                ("ls", "/proc/irq"): "",
            },
            file_contents={
                "/sys/devices/system/cpu/online": "0-7",
                "/proc/cmdline": "isolcpus=2-5 nohz_full=2-5 rcu_nocbs=2-5",
            }
        )
        output = Output()

        exit_code = cpu_isolation.run(["--verbose"], output, ctx)

        assert exit_code == 0
        assert "online_cpus" in output.data
        assert "cmdline_raw" in output.data
        assert "info" in output.data

    def test_offline_isolated_cpus(self, mock_context):
        """Warns when isolated CPUs are not online."""
        from scripts.baremetal import cpu_isolation

        ctx = mock_context(
            tools_available=["ls"],
            command_outputs={
                ("ls", "/proc/irq"): "",
            },
            file_contents={
                "/sys/devices/system/cpu/online": "0-3",  # Only 4 CPUs online
                "/proc/cmdline": "isolcpus=2-7 nohz_full=2-7 rcu_nocbs=2-7",  # Tries to isolate 8
            }
        )
        output = Output()

        exit_code = cpu_isolation.run([], output, ctx)

        assert exit_code == 1
        assert any("not online" in w.lower() for w in output.data["warnings"])

    def test_isolcpus_with_flags(self, mock_context):
        """Parses isolcpus with flags like 'domain,managed_irq'."""
        from scripts.baremetal import cpu_isolation

        ctx = mock_context(
            tools_available=["ls"],
            command_outputs={
                ("ls", "/proc/irq"): "",
            },
            file_contents={
                "/sys/devices/system/cpu/online": "0-7",
                "/proc/cmdline": "isolcpus=domain,managed_irq,2-5",
            }
        )
        output = Output()

        exit_code = cpu_isolation.run([], output, ctx)

        # Should parse correctly despite flags
        assert output.data["isolation"]["isolcpus"] == [2, 3, 4, 5]
