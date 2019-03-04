"""Tests for getters."""

from napalm.base.test.getters import BaseTestGetters
from napalm.base.test import helpers
from napalm.base.test.getters import wrap_test_cases
from napalm.base.utils.py23_compat import text_type

import pytest


@pytest.mark.usefixtures("set_device_parameters")
class TestGetter(BaseTestGetters):
    """Test get_* methods."""

    @wrap_test_cases
    def test_get_facts(self, test_case):
        """Test get_facts method."""
        modale_facts = {
            "os_version": text_type,
            "uptime": int,
            "interface_list": list,
            "vendor": text_type,
            "model": text_type,
            "hostname": text_type,
        }
        facts = self.device.get_facts()
        assert helpers.test_model(modale_facts, facts)
        return facts

    @wrap_test_cases
    def test_get_mac_address_table(self, test_case):
        """Test get_mac_address_table."""
        modale_mac_address_table = {
            "mac": text_type,
            "interface": text_type,
            "type": text_type,
            "vlan": int,
        }
        get_mac_address_table = self.device.get_mac_address_table()
        assert len(get_mac_address_table) > 0

        for mac_table_entry in get_mac_address_table:
            assert helpers.test_model(modale_mac_address_table, mac_table_entry)

        return get_mac_address_table

    @wrap_test_cases
    def test_get_arp_table(self, test_case):
        """Test get_arp_table."""
        modale_arp_table = {"interface": text_type, "mac": text_type, "ip": text_type, "type": text_type}
        get_arp_table = self.device.get_arp_table()
        assert len(get_arp_table) > 0

        for arp_entry in get_arp_table:
            assert helpers.test_model(modale_arp_table, arp_entry)

        return get_arp_table

    @wrap_test_cases
    def test_get_arp_table_with_vrf(self, test_case):
        """Test get_arp_table with vrf."""
        raise NotImplementedError

    @wrap_test_cases
    def test_get_interfaces(self, test_case):
        """There is little to test with this function."""
        raise NotImplementedError

    def test_method_signatures(self):
        """Test that all methods have the same signature.

        There is little to test with this function.
        """
        pass
