"""Tests for binfmt_audit script."""

import pytest

from boxctl.core.output import Output


BINFMT_QEMU_ARM = """enabled
interpreter /usr/bin/qemu-arm-static
flags: F
offset 0
magic 7f454c4601010100000000000000000002002800
mask ffffffffffffff00fffffffffffffffffeffffff
"""

BINFMT_WINE = """enabled
interpreter /usr/bin/wine
flags:
offset 0
magic 4d5a
"""

BINFMT_DISABLED = """disabled
interpreter /usr/bin/some-handler
flags:
"""


class TestBinfmtAudit:
    """Tests for binfmt_audit script."""

    def test_binfmt_not_mounted(self, mock_context):
        """Returns 0 when binfmt_misc not mounted."""
        from scripts.baremetal import binfmt_audit

        ctx = mock_context(
            tools_available=["ls"],
            file_contents={},
        )
        output = Output()

        exit_code = binfmt_audit.run([], output, ctx)

        assert exit_code == 0
        assert output.data["binfmt_misc_enabled"] is False

    def test_no_handlers_registered(self, mock_context):
        """Returns 0 when no handlers registered."""
        from scripts.baremetal import binfmt_audit

        ctx = mock_context(
            tools_available=["ls"],
            command_outputs={
                ("ls", "/proc/sys/fs/binfmt_misc"): "register\nstatus\n",
            },
            file_contents={
                "/proc/sys/fs/binfmt_misc": "",
                "/proc/sys/fs/binfmt_misc/status": "enabled",
            }
        )
        output = Output()

        exit_code = binfmt_audit.run([], output, ctx)

        assert exit_code == 0
        assert output.data["binfmt_misc_enabled"] is True
        assert output.data["total_handlers"] == 0

    def test_qemu_handler_detected(self, mock_context):
        """Returns 1 when QEMU handler detected (high risk)."""
        from scripts.baremetal import binfmt_audit

        ctx = mock_context(
            tools_available=["ls"],
            command_outputs={
                ("ls", "/proc/sys/fs/binfmt_misc"): "register\nstatus\nqemu-arm\n",
            },
            file_contents={
                "/proc/sys/fs/binfmt_misc": "",
                "/proc/sys/fs/binfmt_misc/status": "enabled",
                "/proc/sys/fs/binfmt_misc/qemu-arm": BINFMT_QEMU_ARM,
                "/usr/bin/qemu-arm-static": "binary",
            }
        )
        output = Output()

        exit_code = binfmt_audit.run([], output, ctx)

        assert exit_code == 1
        assert output.data["total_handlers"] == 1
        assert len(output.data["analysis"]["issues"]) > 0
        assert any("qemu" in i.lower() for i in output.data["analysis"]["issues"])

    def test_wine_handler_detected(self, mock_context):
        """Returns 1 when Wine handler detected (high risk)."""
        from scripts.baremetal import binfmt_audit

        ctx = mock_context(
            tools_available=["ls"],
            command_outputs={
                ("ls", "/proc/sys/fs/binfmt_misc"): "register\nstatus\nwine\n",
            },
            file_contents={
                "/proc/sys/fs/binfmt_misc": "",
                "/proc/sys/fs/binfmt_misc/status": "enabled",
                "/proc/sys/fs/binfmt_misc/wine": BINFMT_WINE,
                "/usr/bin/wine": "binary",
            }
        )
        output = Output()

        exit_code = binfmt_audit.run([], output, ctx)

        assert exit_code == 1
        assert any("wine" in i.lower() for i in output.data["analysis"]["issues"])

    def test_disabled_handler_ignored(self, mock_context):
        """Disabled handlers don't generate issues."""
        from scripts.baremetal import binfmt_audit

        ctx = mock_context(
            tools_available=["ls"],
            command_outputs={
                ("ls", "/proc/sys/fs/binfmt_misc"): "register\nstatus\nsome-handler\n",
            },
            file_contents={
                "/proc/sys/fs/binfmt_misc": "",
                "/proc/sys/fs/binfmt_misc/status": "enabled",
                "/proc/sys/fs/binfmt_misc/some-handler": BINFMT_DISABLED,
            }
        )
        output = Output()

        exit_code = binfmt_audit.run([], output, ctx)

        assert exit_code == 0
        assert len(output.data["analysis"]["issues"]) == 0

    def test_allowed_handler_skipped(self, mock_context):
        """Allowed handlers don't generate issues."""
        from scripts.baremetal import binfmt_audit

        ctx = mock_context(
            tools_available=["ls"],
            command_outputs={
                ("ls", "/proc/sys/fs/binfmt_misc"): "register\nstatus\nqemu-arm\n",
            },
            file_contents={
                "/proc/sys/fs/binfmt_misc": "",
                "/proc/sys/fs/binfmt_misc/status": "enabled",
                "/proc/sys/fs/binfmt_misc/qemu-arm": BINFMT_QEMU_ARM,
                "/usr/bin/qemu-arm-static": "binary",
            }
        )
        output = Output()

        exit_code = binfmt_audit.run(["--allow", "qemu-arm"], output, ctx)

        assert exit_code == 0
        assert len(output.data["analysis"]["issues"]) == 0

    def test_verbose_includes_handlers(self, mock_context):
        """--verbose includes handler details."""
        from scripts.baremetal import binfmt_audit

        ctx = mock_context(
            tools_available=["ls"],
            command_outputs={
                ("ls", "/proc/sys/fs/binfmt_misc"): "register\nstatus\nsome-handler\n",
            },
            file_contents={
                "/proc/sys/fs/binfmt_misc": "",
                "/proc/sys/fs/binfmt_misc/status": "enabled",
                "/proc/sys/fs/binfmt_misc/some-handler": BINFMT_DISABLED,
            }
        )
        output = Output()

        exit_code = binfmt_audit.run(["--verbose"], output, ctx)

        assert exit_code == 0
        assert "handlers" in output.data
        assert len(output.data["handlers"]) == 1

    def test_missing_interpreter_warning(self, mock_context):
        """Warns when interpreter path doesn't exist."""
        from scripts.baremetal import binfmt_audit

        qemu_entry = """enabled
interpreter /nonexistent/qemu-arm
flags:
"""

        ctx = mock_context(
            tools_available=["ls"],
            command_outputs={
                ("ls", "/proc/sys/fs/binfmt_misc"): "register\nstatus\nqemu-arm\n",
            },
            file_contents={
                "/proc/sys/fs/binfmt_misc": "",
                "/proc/sys/fs/binfmt_misc/status": "enabled",
                "/proc/sys/fs/binfmt_misc/qemu-arm": qemu_entry,
                # Note: /nonexistent/qemu-arm NOT in file_contents
            }
        )
        output = Output()

        exit_code = binfmt_audit.run([], output, ctx)

        # Should have issues (QEMU + missing interpreter)
        assert exit_code == 1
        all_messages = output.data["analysis"]["issues"] + output.data["analysis"]["warnings"]
        assert any("not found" in m.lower() or "interpreter" in m.lower() for m in all_messages)
