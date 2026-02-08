"""Tests for lacp_health script."""

import pytest

from boxctl.core.output import Output


BOND_LACP_HEALTHY = """Ethernet Channel Bonding Driver: v5.15.0

Bonding Mode: IEEE 802.3ad Dynamic link aggregation
Transmit Hash Policy: layer3+4 (1)
MII Status: up
MII Polling Interval (ms): 100
802.3ad info
LACP rate: fast
Min links: 0

Slave Interface: eth0
MII Status: up
Speed: 10000 Mbps
Duplex: full
Aggregator ID: 1
Partner Mac Address: 00:11:22:33:44:55

Slave Interface: eth1
MII Status: up
Speed: 10000 Mbps
Duplex: full
Aggregator ID: 1
Partner Mac Address: 00:11:22:33:44:55
"""

BOND_PARTNER_MISMATCH = """Ethernet Channel Bonding Driver: v5.15.0

Bonding Mode: IEEE 802.3ad Dynamic link aggregation
LACP rate: fast

Slave Interface: eth0
MII Status: up
Aggregator ID: 1
Partner Mac Address: 00:11:22:33:44:55

Slave Interface: eth1
MII Status: up
Aggregator ID: 1
Partner Mac Address: aa:bb:cc:dd:ee:ff
"""

BOND_SLAVE_DOWN = """Ethernet Channel Bonding Driver: v5.15.0

Bonding Mode: IEEE 802.3ad Dynamic link aggregation
LACP rate: fast

Slave Interface: eth0
MII Status: up
Aggregator ID: 1
Partner Mac Address: 00:11:22:33:44:55

Slave Interface: eth1
MII Status: down
Aggregator ID: 1
Partner Mac Address: 00:00:00:00:00:00
"""

BOND_SPLIT_AGG = """Ethernet Channel Bonding Driver: v5.15.0

Bonding Mode: IEEE 802.3ad Dynamic link aggregation
LACP rate: fast

Slave Interface: eth0
MII Status: up
Aggregator ID: 1
Partner Mac Address: 00:11:22:33:44:55

Slave Interface: eth1
MII Status: up
Aggregator ID: 2
Partner Mac Address: 00:11:22:33:44:55
"""

BOND_ACTIVE_BACKUP = """Ethernet Channel Bonding Driver: v5.15.0

Bonding Mode: fault-tolerance (active-backup)
Primary Slave: None
Currently Active Slave: eth0
MII Status: up

Slave Interface: eth0
MII Status: up

Slave Interface: eth1
MII Status: up
"""


class TestLacpHealth:
    """Tests for lacp_health script."""

    def test_no_bond_interfaces(self, mock_context):
        """Returns 0 when no bond interfaces found."""
        from scripts.baremetal.lacp_health import run

        ctx = mock_context(file_contents={})
        output = Output()

        assert run([], output, ctx) == 0
        assert len(output.data['bonds']) == 0

    def test_healthy_lacp(self, mock_context):
        """Returns 0 when LACP bond is healthy."""
        from scripts.baremetal.lacp_health import run

        ctx = mock_context(file_contents={
            '/proc/net/bonding/bond0': BOND_LACP_HEALTHY,
        })
        output = Output()

        assert run([], output, ctx) == 0

    def test_partner_mac_mismatch(self, mock_context):
        """Returns 1 when partner MACs differ across slaves."""
        from scripts.baremetal.lacp_health import run

        ctx = mock_context(file_contents={
            '/proc/net/bonding/bond0': BOND_PARTNER_MISMATCH,
        })
        output = Output()

        assert run([], output, ctx) == 1
        assert any(i['type'] == 'partner_mac_mismatch' for i in output.data['issues'])

    def test_slave_down(self, mock_context):
        """Returns 1 when a slave MII Status is down."""
        from scripts.baremetal.lacp_health import run

        ctx = mock_context(file_contents={
            '/proc/net/bonding/bond0': BOND_SLAVE_DOWN,
        })
        output = Output()

        assert run([], output, ctx) == 1
        assert any(i['type'] == 'slave_down' for i in output.data['issues'])

    def test_split_aggregation(self, mock_context):
        """Returns 1 when Aggregator IDs differ across slaves."""
        from scripts.baremetal.lacp_health import run

        ctx = mock_context(file_contents={
            '/proc/net/bonding/bond0': BOND_SPLIT_AGG,
        })
        output = Output()

        assert run([], output, ctx) == 1
        assert any(i['type'] == 'split_aggregation' for i in output.data['issues'])

    def test_non_lacp_bond(self, mock_context):
        """Returns 0 when bond is not in LACP mode."""
        from scripts.baremetal.lacp_health import run

        ctx = mock_context(file_contents={
            '/proc/net/bonding/bond0': BOND_ACTIVE_BACKUP,
        })
        output = Output()

        assert run([], output, ctx) == 0
        assert any(i['type'] == 'non_lacp' for i in output.data['issues'])

    def test_json_output(self, mock_context):
        """Verify JSON data structure."""
        from scripts.baremetal.lacp_health import run

        ctx = mock_context(file_contents={
            '/proc/net/bonding/bond0': BOND_LACP_HEALTHY,
        })
        output = Output()

        run(["--format", "json"], output, ctx)

        assert 'bonds' in output.data
        assert 'issues' in output.data
