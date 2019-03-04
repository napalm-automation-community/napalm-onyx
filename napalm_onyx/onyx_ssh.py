# -*- coding: utf-8 -*-
# Copyright 2015 Spotify AB. All rights reserved.
#
# The contents of this file are licensed under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with the
# License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under
# the License.

"""
Napalm driver for Onyx.

Read https://napalm.readthedocs.io for more information.
"""

from __future__ import unicode_literals

# import stdlib
import re
import json
import os
import uuid
import tempfile
import hashlib
import socket

# import third party lib

# import NAPALM Base
from napalm.base import NetworkDriver
import napalm.base.helpers
from napalm.base import helpers
from napalm.base.netmiko_helpers import netmiko_args
from napalm.base.utils import py23_compat
from napalm.base.exceptions import MergeConfigException
from napalm.base.exceptions import CommandErrorException
from napalm.base.exceptions import ReplaceConfigException
import napalm.base.constants as c

# Easier to store these as constants
HOUR_SECONDS = 3600
DAY_SECONDS = 24 * HOUR_SECONDS
WEEK_SECONDS = 7 * DAY_SECONDS
YEAR_SECONDS = 365 * DAY_SECONDS

# STD REGEX PATTERNS
IP_ADDR_REGEX = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
IPV4_ADDR_REGEX = IP_ADDR_REGEX
IPV6_ADDR_REGEX_1 = r"::"
IPV6_ADDR_REGEX_2 = r"[0-9a-fA-F:]{1,39}::[0-9a-fA-F:]{1,39}"
IPV6_ADDR_REGEX_3 = r"[0-9a-fA-F]{1,3}:[0-9a-fA-F]{1,3}:[0-9a-fA-F]{1,3}:[0-9a-fA-F]{1,3}:" \
                     r"[0-9a-fA-F]{1,3}:[0-9a-fA-F]{1,3}:[0-9a-fA-F]{1,3}:[0-9a-fA-F]{1,3}"
# Should validate IPv6 address using an IP address library after matching with this regex
IPV6_ADDR_REGEX = r"(?:{}|{}|{})".format(IPV6_ADDR_REGEX_1, IPV6_ADDR_REGEX_2, IPV6_ADDR_REGEX_3)
IPV4_OR_IPV6_REGEX = r"(?:{}|{})".format(IPV4_ADDR_REGEX, IPV6_ADDR_REGEX)

MAC_REGEX = r"[a-fA-F0-9:]{17}|[a-fA-F0-9]{12}$"
VLAN_REGEX = r"\d{1,4}"

RE_IPADDR = re.compile(r"{}".format(IP_ADDR_REGEX))
RE_MAC = re.compile(r"{}".format(MAC_REGEX))

# Period needed for 32-bit AS Numbers
ASN_REGEX = r"[\d\.]+"


def parse_intf_section(interface):
    """Parse a single entry from show interfaces output.

    Different cases:
    mgmt0 is up
    admin state is up

    Ethernet2/1 is up
    admin state is up, Dedicated Interface

    Vlan1 is down (Administratively down), line protocol is down, autostate enabled

    Ethernet154/1/48 is up (with no 'admin state')
    """
    raise NotImplementedError("parse_intf_section is not supported yet for onyx devices")


def convert_hhmmss(hhmmss):
    """Convert hh:mm:ss to seconds."""
    fields = hhmmss.split(":")
    if len(fields) != 3:
        raise ValueError("Received invalid HH:MM:SS data: {}".format(hhmmss))
    fields = [int(x) for x in fields]
    hours, minutes, seconds = fields
    return (hours * 3600) + (minutes * 60) + seconds


def bgp_time_conversion(bgp_uptime):
    """Convert string time to seconds."""
    raise NotImplementedError("bgp_time_conversion is not supported yet for onyx devices")


def bgp_normalize_table_data(bgp_table):
    """Show bgp all summary vrf all table can have entries that wrap multiple lines.

    2001:db8:4:701::2
                4 65535  163664  163693      145    0    0     3w2d 3
    2001:db8:e0:dd::1
                4    10  327491  327278      145    0    0     3w1d 4

    Normalize this so the line wrap doesn't exit.
    """
    raise NotImplementedError("bgp_table_parser is not supported yet for onyx devices")


def bgp_table_parser(bgp_table):
    """Generate that parses a line of bgp summary table and returns a dict compatible with NAPALM

    Example line:
    10.2.1.14       4    10  472516  472238      361    0    0     3w1d 9
    """
    raise NotImplementedError("bgp_table_parser is not supported yet for onyx devices")


def bgp_summary_parser(bgp_summary):
    """Parse 'show bgp all summary vrf' output information from NX-OS devices."""
    raise NotImplementedError("bgp_summary_parser is not supported yet for onyx devices")


class ONYXSSHDriver(NetworkDriver):
    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        """Initialization function for ONYXSSHDriver Class."""
        if optional_args is None:
            optional_args = {}
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.replace = True
        self.loaded = False
        self.changed = False
        self.up = False
        self.replace_file = None
        self.merge_candidate = ''
        self.netmiko_optional_args = netmiko_args(optional_args)
        self.device = None

    def open(self):
        self.device = self._netmiko_open(
            device_type='mellanox',
            netmiko_optional_args=self.netmiko_optional_args,
        )
        if self.device is not None:
            self.up = True

    def close(self):
        if self.changed:
            self._delete_file(self.backup_file)
        self._netmiko_close()

    def _send_command(self, command):
        """Wrapper for Netmiko's send_command method."""
        return self.device.send_command(command)

    @staticmethod
    def parse_uptime(uptime_str):
        """Extract the uptime string from the given Cisco IOS Device.

        Return the uptime in seconds as an integer
        """
        # Initialize to zero
        (years, weeks, days, hours, minutes) = (0, 0, 0, 0, 0)

        uptime_str = uptime_str.strip()
        time_list = uptime_str.split(" ")
        for element in time_list:
            if re.search("y", element):
                years = int(element.split("y")[0])
            elif re.search("w", element):
                weeks = int(element.split("w")[0])
            elif re.search("d", element):
                days = int(element.split("d")[0])
            elif re.search("h", element):
                hours = int(element.split("h")[0])
            elif re.search("m", element):
                minutes = int(element.split("m")[0])
            elif re.search("s", element):
                seconds = float(element.split("s")[0])

        uptime_sec = ((years * YEAR_SECONDS) + (weeks * WEEK_SECONDS) + (
            days * DAY_SECONDS) + (hours * 3600) + (minutes * 60) + seconds)
        return uptime_sec

    def ping(self,
             destination,
             source=c.PING_SOURCE,
             ttl=c.PING_TTL,
             timeout=c.PING_TIMEOUT,
             size=c.PING_SIZE,
             count=c.PING_COUNT,
             vrf=c.PING_VRF):
        """
        Execute ping on the device and returns a dictionary with the result.

        Output dictionary has one of following keys:
            * success
            * error
        In case of success, inner dictionary will have the followin keys:
            * probes_sent (int)
            * packet_loss (int)
            * rtt_min (float)
            * rtt_max (float)
            * rtt_avg (float)
            * rtt_stddev (float)
            * results (list)
        'results' is a list of dictionaries with the following keys:
            * ip_address (str)
            * rtt (float)
        """
        raise NotImplementedError("ping is not supported yet for onyx devices")

    def is_alive(self):
        """Returns a flag with the state of the SSH connection."""
        null = chr(0)
        try:
            if self.device is None:
                return {'is_alive': False}
            else:
                # Try sending ASCII null byte to maintain the connection alive
                self.device.send_command(null)
        except (socket.error, EOFError):
            # If unable to send, we can tell for sure that the connection is unusable,
            # hence return False.
            return {'is_alive': False}
        return {
            'is_alive': self.device.remote_conn.transport.is_active()
        }

    def load_replace_candidate(self, filename=None, config=None):
        self._replace_candidate(filename, config)
        self.replace = True
        self.loaded = True

    def _get_flash_size(self):
        raise NotImplementedError("get_flash_size is not supported yet for onyx devices")

    def _enough_space(self, filename):
        raise NotImplementedError("enough_space is not supported yet for onyx devices")

    def _verify_remote_file_exists(self, dst, file_system='bootflash:'):
        command = 'dir {0}/{1}'.format(file_system, dst)
        output = self.device.send_command(command)
        if 'No such file' in output:
            raise ReplaceConfigException('Could not transfer file.')

    def _replace_candidate(self, filename, config):
        raise NotImplementedError("replace_candidate is not supported yet for onyx devices")

    def _file_already_exists(self, dst):
        dst_hash = self._get_remote_md5(dst)
        src_hash = self._get_local_md5(dst)
        if src_hash == dst_hash:
            return True
        return False

    def _check_file_exists(self, cfg_file):
        command = 'dir {}'.format(cfg_file)
        output = self.device.send_command(command)
        if 'No such file' in output:
            return False
        else:
            return self._file_already_exists(cfg_file)

    def _get_remote_md5(self, dst):
        command = 'show file {0} md5sum'.format(dst)
        return self.device.send_command(command).strip()

    def _get_local_md5(self, dst, blocksize=2**20):
        md5 = hashlib.md5()
        local_file = open(dst, 'rb')
        buf = local_file.read(blocksize)
        while buf:
            md5.update(buf)
            buf = local_file.read(blocksize)
        local_file.close()
        return md5.hexdigest()

    def load_merge_candidate(self, filename=None, config=None):
        self.replace = False
        self.loaded = True

        if not filename and not config:
            raise MergeConfigException('filename or config param must be provided.')

        self.merge_candidate += '\n'  # insert one extra line
        if filename is not None:
            with open(filename, "r") as f:
                self.merge_candidate += f.read()
        else:
            self.merge_candidate += config

    @staticmethod
    def _create_tmp_file(config):
        tmp_dir = tempfile.gettempdir()
        rand_fname = py23_compat.text_type(uuid.uuid4())
        filename = os.path.join(tmp_dir, rand_fname)
        with open(filename, 'wt') as fobj:
            fobj.write(config)
        return filename

    def _create_sot_file(self):
        """Create Source of Truth file to compare."""
        commands = ['terminal dont-ask', 'checkpoint file sot_file']
        self._send_config_commands(commands)

    def _get_diff(self):
        """Get a diff between running config and a proposed file."""
        diff = []
        self._create_sot_file()
        command = ('show diff rollback-patch file {0} file {1}'.format(
                   'sot_file', self.replace_file.split('/')[-1]))
        diff_out = self.device.send_command(command)
        try:
            diff_out = diff_out.split(
                'Generating Rollback Patch')[1].replace(
                    'Rollback Patch is Empty', '').strip()
            for line in diff_out.splitlines():
                if line:
                    if line[0].strip() != '!' and line[0].strip() != '.':
                        diff.append(line.rstrip(' '))
        except (AttributeError, KeyError):
            raise ReplaceConfigException(
                'Could not calculate diff. It\'s possible the given file doesn\'t exist.')
        return '\n'.join(diff)

    def _get_merge_diff(self):
        diff = []
        running_config = self.get_config(retrieve='running')['running']
        running_lines = running_config.splitlines()
        for line in self.merge_candidate.splitlines():
            if line not in running_lines and line:
                if line[0].strip() != '!':
                    diff.append(line)
        return '\n'.join(diff)
        # the merge diff is not necessarily what needs to be loaded
        # for example under NTP, as the `ntp commit` command might be
        # alread configured, it is mandatory to be sent
        # otherwise it won't take the new configuration - see #59
        # https://github.com/napalm-automation/napalm-nxos/issues/59
        # therefore this method will return the real diff
        # but the merge_candidate will remain unchanged
        # previously: self.merge_candidate = '\n'.join(diff)

    def compare_config(self):
        if self.loaded:
            if not self.replace:
                return self._get_merge_diff()
                # return self.merge_candidate
            diff = self._get_diff()
            return diff
        return ''

    def _copy_run_start(self, filename='startup-config'):
        command = 'copy run {}'.format(filename)
        output = self.device.send_command(command)
        if 'complete' in output.lower():
            return True
        else:
            msg = 'Unable to save running-config to {}!'.format(filename)
            raise CommandErrorException(msg)

    def _commit_merge(self):
        try:
            commands = [command for command in self.merge_candidate.splitlines() if command]
            output = self.device.send_config_set(commands)
        except Exception as e:
            raise MergeConfigException(str(e))
        if 'Invalid command' in output:
            raise MergeConfigException('Error while applying config!')
        # clear the merge buffer
        self.merge_candidate = ''

    def _save_to_checkpoint(self, filename):
        """Save the current running config to the given file."""
        command = 'checkpoint file {}'.format(filename)
        self.device.send_command(command)

    def _disable_confirmation(self):
        self._send_config_commands(['terminal dont-ask'])

    def _load_cfg_from_checkpoint(self):
        command = 'rollback running file {0}'.format(self.replace_file.split('/')[-1])
        self._disable_confirmation()
        rollback_result = self.device.send_command(command)
        if 'Rollback failed.' in rollback_result or 'ERROR' in rollback_result:
            raise ReplaceConfigException(rollback_result)
        elif rollback_result == []:
            raise ReplaceConfigException

    def _delete_file(self, filename):
        commands = [
            'terminal dont-ask',
            'delete {}'.format(filename),
            'no terminal dont-ask'
        ]
        for command in commands:
            self.device.send_command(command)

    def discard_config(self):
        if self.loaded:
            self.merge_candidate = ''  # clear the buffer
        if self.loaded and self.replace:
            self._delete_file(self.replace_file)
        self.loaded = False

    def rollback(self):
        if self.changed:
            command = 'rollback running-config file {}'.format(self.backup_file)
            result = self.device.send_command(command)
            if 'completed' not in result.lower():
                raise ReplaceConfigException(result)
            self._copy_run_start()
            self.changed = False

    def _apply_key_map(self, key_map, table):
        new_dict = {}
        for key, value in table.items():
            new_key = key_map.get(key)
            if new_key:
                new_dict[new_key] = str(value)
        return new_dict

    def _convert_uptime_to_seconds(self, uptime_facts):
        seconds = int(uptime_facts['up_days']) * 24 * 60 * 60
        seconds += int(uptime_facts['up_hours']) * 60 * 60
        seconds += int(uptime_facts['up_mins']) * 60
        seconds += int(uptime_facts['up_secs'])
        return seconds

    def get_facts(self):
        """Return a set of facts from the devices."""
        # default values.
        vendor = "Mellanox"
        uptime = -1
        os_version, hostname, model = ("",) * 3

        # obtain output from device
        show_ver = self._send_command("show version")
        show_hosts = self._send_command("show hosts")
        show_int_status = self._send_command("show interface status")

        # uptime/serial_number/IOS version
        for line in show_ver.splitlines():
            if "Uptime:" in line:
                _, uptime_str = line.split("Uptime:")
                uptime = self.parse_uptime(uptime_str)

            if "Product release:" in line:
                line = line.strip()
                os_version = line.split()[2]
                os_version = os_version.strip()

            if "Product model:" in line:
                line = line.strip()
                model = line.split()[2]

        for line in show_hosts.splitlines():
            if "Hostname: " in line:
                _, hostname = line.split("Hostname: ")
                break

        interface_list = []
        for line in show_int_status.splitlines():
            if line == '':
                continue
            elif line.startswith('E') or line.startswith('m'):
                interface = line.split()[0]
                # Return canonical interface name
                interface_list.append(helpers.canonical_interface_name(interface))

        return {
            "uptime": int(uptime),
            "vendor": vendor,
            "os_version": py23_compat.text_type(os_version),
            "model": py23_compat.text_type(model),
            "hostname": py23_compat.text_type(hostname),
            "interface_list": interface_list,
        }

    def get_interfaces(self):
        """
        Get interface details.

        last_flapped is not implemented

        Example Output:

        {   u'Vlan1': {   'description': u'',
                      'is_enabled': True,
                      'is_up': True,
                      'last_flapped': -1.0,
                      'mac_address': u'a493.4cc1.67a7',
                      'speed': 100},
        u'Vlan100': {   'description': u'Data Network',
                        'is_enabled': True,
                        'is_up': True,
                        'last_flapped': -1.0,
                        'mac_address': u'a493.4cc1.67a7',
                        'speed': 100},
        u'Vlan200': {   'description': u'Voice Network',
                        'is_enabled': True,
                        'is_up': True,
                        'last_flapped': -1.0,
                        'mac_address': u'a493.4cc1.67a7',
                        'speed': 100}}
        """
        no_paging_enable_command = 'no cli session paging enable'
        self.device.send_command(no_paging_enable_command)
        command = 'show interfaces | json-print'
        output = self.device.send_command(command)
        if not output:
            return {}

        return output

    def disable_paging(self):
        """Run 'no cli session paging enable' command on switch."""
        no_paging_enable_command = 'no cli session paging enable'
        self.device.disable_paging(command=no_paging_enable_command)

    def enable(self):
        """Run 'enable' command on switch."""
        self.device.enable(cmd='enable', pattern=r'\s#\s')

    def config_terminal(self):
        """Run 'configure terminal' command on switch."""
        self.device.config_mode(config_command='configure terminal', pattern=r'\(config\)')

    def exit(self):
        """Exist from enable mode for switch."""
        self.device.send_command("exit", expect_string=r'\(config\)')

    def show_vlans(self):
        """Return a lists of created vlans on switch"""
        self.disable_paging()
        command = 'show vlan | json-print'
        output = self.device.send_command(command)
        return output

    def get_vlan(self, vlan_id):
        """Get Vlan details."""
        no_paging_enable_command = 'no cli session paging enable'
        self.device.send_command(no_paging_enable_command)
        command = 'show vlan id {0} | json-print'.format(vlan_id)
        output = self.device.send_command(command)
        return output

    def create_vlan(self, vlan_id, interfaces):
        """Create vlan on switch and add interfaces to it."""
        no_paging_enable_command = 'no cli session paging enable'
        self.device.disable_paging(command=no_paging_enable_command)
        vlan = self.get_vlan(vlan_id)
        vlan = json.loads(vlan)
        if not vlan:
            self.device.enable(cmd='enable', pattern=r'\s#\s')
            self.device.config_mode(config_command='configure terminal', pattern=r'\(config\)')
            self.device.send_command("vlan {0}".format(vlan_id), expect_string=r'\(config vlan')
            self.device.send_command("exit", expect_string=r'\(config\)')
            if interfaces is not None:
                if type(interfaces) is not list:
                    raise TypeError('Please enter a valid list of interfaces!')
                for interface in interfaces:
                    interface = interface.replace('Eth', 'ethernet ')
                    self.device.send_command("interface {0} switchport access vlan {1}".format(interface, vlan_id))
                    return 'Created Vlan with id {} has Done Successfully'.format(vlan_id)

    def get_lldp_neighbors(self):
        raise NotImplementedError("get_lldp_neighbors is not supported yet for onyx devices")

    def get_bgp_neighbors(self):
        raise NotImplementedError("get_bgp_neighbors is not supported yet for onyx devices")

    def _send_config_commands(self, commands):
        for command in commands:
            self.device.send_command(command)

    def _set_checkpoint(self, filename):
        commands = ['terminal dont-ask', 'checkpoint file {0}'.format(filename)]
        self._send_config_commands(commands)

    def _get_checkpoint_file(self):
        filename = 'temp_cp_file_from_napalm'
        self._set_checkpoint(filename)
        command = 'show file {0}'.format(filename)
        output = self.device.send_command(command)
        self._delete_file(filename)
        return output

    def get_lldp_neighbors_detail(self, interface=''):
        raise NotImplementedError("get_lldp_neighbors_detail is not supported yet for onyx devices")

    def cli(self, commands):
        cli_output = {}
        if type(commands) is not list:
            raise TypeError('Please enter a valid list of commands!')

        for command in commands:
            output = self.device.send_command(command)
            cli_output[py23_compat.text_type(command)] = output
        return cli_output

    def get_arp_table(self):
        """Get arp table information.

        Return a list of dictionaries having the following set of keys:
            * interface (string)
            * mac (string)
            * ip (string)
            * type (string)

        For example::
            [
                {
                    'interface' : 'MgmtEth0/RSP0/CPU0/0',
                    'mac'       : '5c:5e:ab:da:3c:f0',
                    'ip'        : '172.17.17.1',
                    'age'       : 12.0
                },
                {
                    'interface': 'MgmtEth0/RSP0/CPU0/0',
                    'mac'       : '66:0e:94:96:e0:ff',
                    'ip'        : '172.17.17.2',
                    'type'       : Ethernet
                }
            ]
        """
        arp_table = []

        command = 'show ip arp'
        output = self.device.send_command(command)
        output = output.split('\n')
        arp_entries = output[7:-1]

        for line in arp_entries:
            if line == '':
                continue
            elif len(line.split()) >= 5:
                # Search for extra characters to strip, currently strip '*', '+', '#', 'D'
                line = re.sub(r"\s+[\*\+\#D]{1,4}\s*$", "", line, flags=re.M)
                line_list = line.split()
                address = line_list[0]
                type = line_list[1] + ' ' + line_list[2]
                mac = line_list[3]
                interface = line_list[4]
            else:
                raise ValueError("Unexpected output from: {}".format(line.split()))

            # Validate we matched correctly
            if not re.search(RE_IPADDR, address):
                raise ValueError("Invalid IP Address detected: {}".format(address))
            if not re.search(RE_MAC, mac):
                raise ValueError("Invalid MAC Address detected: {}".format(mac))
            entry = {
                'interface': interface,
                'mac': napalm.base.helpers.mac(mac),
                'ip': address,
                'type': type
            }
            arp_table.append(entry)
        return arp_table

    def _get_ntp_entity(self, peer_type):
        raise NotImplementedError("_get_ntp_entity is not supported yet for onyx devices")

    def get_ntp_peers(self):
        return self._get_ntp_entity('Peer')

    def get_ntp_servers(self):
        return self._get_ntp_entity('Server')

    def __get_ntp_stats(self):
        raise NotImplementedError("__get_ntp_stats is not supported yet for onyx devices")

    def get_interfaces_ip(self):
        raise NotImplementedError("get_interfaces_ip is not supported yet for onyx devices")

    def get_mac_address_table(self):
        """Return a lists of dictionaries. Each dictionary represents an entry in the MAC Address

        Table, having the following keys
            * mac (string)
            * interface (string)
            * vlan (int)
            * mac_type (string)
        Format1:

        Legend:
        * - primary entry, G - Gateway MAC, (R) - Routed MAC, O - Overlay MAC
        age - seconds since last seen,+ - primary entry using vPC Peer-Link,
        (T) - True, (F) - False
        ---------------------------------------------------
        Vlan    Mac Address         Type         Port
        ---------------------------------------------------
        1       E4:1D:2D:66:DF:9B   Dynamic      Eth1/19
        1       EC:0D:9A:42:EA:00   Dynamic      Eth1/19
        1       EC:0D:9A:42:EA:01   Dynamic      Eth1/31


        Number of unicast:    3
        Number of multicast:  0
        """
        mac_address_table = []
        command = 'show mac-address-table'
        mac_table_output = self.device.send_command(command)
        output = mac_table_output.split('\n')
        mac_entries = output[3:-5]

        for line in mac_entries:
            if len(line.split()) >= 4:
                line = re.sub(r"\s+[\*\+\#D]{1,4}\s*$", "", line, flags=re.M)
                line_list = line.split()
                vlan = line_list[0]
                mac = line_list[1]
                mac_type = line_list[2]
                interface = line_list[3]
                mac_address_table.append({
                    'mac': napalm.base.helpers.mac(mac),
                    'interface': interface,
                    'vlan': int(vlan),
                    'type': mac_type
                })
            else:
                raise ValueError("Unexpected output from: {}".format(line.split()))

        return mac_address_table

    def get_snmp_information(self):
        raise NotImplementedError("get_snmp_information is not supported yet for onyx devices")

    def get_users(self):
        raise NotImplementedError("get_users is not supported yet for onyx devices")

    def traceroute(self,
                   destination,
                   source=c.TRACEROUTE_SOURCE,
                   ttl=c.TRACEROUTE_TTL,
                   timeout=c.TRACEROUTE_TIMEOUT,
                   vrf=c.TRACEROUTE_VRF):

        raise NotImplementedError("traceroute is not supported yet for onyx devices")

    def get_config(self, retrieve='all'):
        raise NotImplementedError("get_config is not supported yet for onyx devices")
