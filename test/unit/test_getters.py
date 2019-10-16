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
        module_facts = {
            "os_version": text_type,
            "uptime": int,
            "interface_list": list,
            "vendor": text_type,
            "model": text_type,
            "hostname": text_type,
        }
        facts = self.device.get_facts()
        assert helpers.test_model(module_facts, facts)
        return facts

    @wrap_test_cases
    def test_get_mac_address_table(self, test_case):
        """Test get_mac_address_table."""
        module_mac_address_table = {
            "mac": text_type,
            "interface": text_type,
            "type": text_type,
            "vlan": int,
        }
        get_mac_address_table = self.device.get_mac_address_table()
        assert len(get_mac_address_table) > 0

        for mac_table_entry in get_mac_address_table:
            assert helpers.test_model(module_mac_address_table, mac_table_entry)

        return get_mac_address_table

    @wrap_test_cases
    def test_get_arp_table(self, test_case):
        """Test get_arp_table."""
        module_arp_table = {"interface": text_type, "mac": text_type, "ip": text_type, "type": text_type}
        get_arp_table = self.device.get_arp_table()
        assert len(get_arp_table) > 0

        for arp_entry in get_arp_table:
            assert helpers.test_model(module_arp_table, arp_entry)

        return get_arp_table

    @wrap_test_cases
    def test_get_arp_table_with_vrf(self, test_case):
        """Test get_arp_table with vrf."""
        raise NotImplementedError

    @wrap_test_cases
    def test_get_interfaces(self, test_case):
        """There is little to test with this function."""
        raise NotImplementedError

    @wrap_test_cases
    def test_get_lldp_neighbors(self, test_case):
        get_lldp_neighbors = self.device.get_lldp_neighbors()
        assert len(get_lldp_neighbors) > 0
        return get_lldp_neighbors

    def test_method_signatures(self):
        """Test that all methods have the same signature.

        There is little to test with this function.
        """
        pass

    @wrap_test_cases
    def test_get_config(self, test_case):
        """Test get_config."""
        get_config = self.device.get_config()
        assert get_config.get('running') != '' and get_config.get('startup') != ''
        return get_config

    @wrap_test_cases
    def test_get_config_filtered(self, test_case):
        """Test get_config filtered."""
        get_startup = self.device.get_config('startup')
        get_running = self.device.get_config('running')
        assert get_running != '' and get_startup != ''
        return {'running': get_running, 'startup': get_startup}
