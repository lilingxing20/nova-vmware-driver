# Copyright (c) 2013 Hewlett-Packard Development Company, L.P.
# Copyright (c) 2012 VMware, Inc.
# Copyright (c) 2011 Citrix Systems, Inc.
# Copyright 2011 OpenStack Foundation
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
"""
The VMware API VM utility module to build SOAP object specs.
"""
 
# Vsettan-only start
import uuid
import re
import traceback
import base64
from IPy import IP
from operator import itemgetter
from xml.dom import minidom
from oslo_utils import encodeutils
# Vsettan-only end

import collections
import copy
import functools

from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import excutils
from oslo_utils import units
from oslo_vmware import exceptions as vexc
from oslo_vmware.objects import datastore as ds_obj
from oslo_vmware import pbm
from oslo_vmware import vim_util as vutil
import six

from nova import exception
from nova import utils # Vsettan-only
from nova.i18n import _, _LE, _LI, _LW
from nova.network import model as network_model
from nova.virt.vcmvmwareapi import constants
from nova.virt.vcmvmwareapi import vim_util

LOG = logging.getLogger(__name__)

vmware_utils_opts = [
    cfg.IntOpt('console_delay_seconds',
               help='Set this value if affected by an increased network '
                    'latency causing repeated characters when typing in '
                    'a remote console.'),
    cfg.StrOpt('serial_port_service_uri',
               help='Identifies the remote system that serial port traffic '
                    'will be sent to. If this is not set, no serial ports '
                    'will be added to the created VMs.'),
    cfg.StrOpt('serial_port_proxy_uri',
               help='Identifies a proxy service that provides network access '
                    'to the serial_port_service_uri. This option is ignored '
                    'if serial_port_service_uri is not specified.'),
    ]

CONF = cfg.CONF
CONF.register_opts(vmware_utils_opts, 'vmware')

ALL_SUPPORTED_NETWORK_DEVICES = ['VirtualE1000', 'VirtualE1000e',
                                 'VirtualPCNet32', 'VirtualSriovEthernetCard',
                                 'VirtualVmxnet', 'VirtualVmxnet3']

# A simple cache for storing inventory folder references.
# Format: {inventory_path: folder_ref}
_FOLDER_PATH_REF_MAPPING = {}

# A cache for VM references. The key will be the VM name
# and the value is the VM reference. The VM name is unique. This
# is either the UUID of the instance or UUID-rescue in the case
# that this is a rescue VM. This is in order to prevent
# unnecessary communication with the backend.
_VM_REFS_CACHE = {}


class Limits(object):

    def __init__(self, limit=None, reservation=None,
                 shares_level=None, shares_share=None):
        """imits object holds instance limits for convenience."""
        self.limit = limit
        self.reservation = reservation
        self.shares_level = shares_level
        self.shares_share = shares_share

    def validate(self):
        if self.shares_level in ('high', 'normal', 'low'):
            if self.shares_share:
                reason = _("Share level '%s' cannot have share "
                           "configured") % self.shares_level
                raise exception.InvalidInput(reason=reason)
            return
        if self.shares_level == 'custom':
            return
        if self.shares_level:
            reason = _("Share '%s' is not supported") % self.shares_level
            raise exception.InvalidInput(reason=reason)

    def has_limits(self):
        return bool(self.limit or
                    self.reservation or
                    self.shares_level)


class ExtraSpecs(object):

    def __init__(self, cpu_limits=None, hw_version=None,
                 storage_policy=None, cores_per_socket=None,
                 memory_limits=None, disk_io_limits=None,
                 vif_limits=None):
        """ExtraSpecs object holds extra_specs for the instance."""
        self.cpu_limits = cpu_limits or Limits()
        self.memory_limits = memory_limits or Limits()
        self.disk_io_limits = disk_io_limits or Limits()
        self.vif_limits = vif_limits or Limits()
        self.hw_version = hw_version
        self.storage_policy = storage_policy
        self.cores_per_socket = cores_per_socket

#Vsettan-only start
def get_vm_name_for_vcenter(instance):
    if CONF.vmware.use_displayname_uuid_for_vmname:
        # Limitation of 80 chars, thus truncate the display_name
        return "%s-%s" % (instance.display_name[0:43], instance.uuid)
    else:
        return instance.uuid
#Vsettan-only end


def vm_refs_cache_reset():
    global _VM_REFS_CACHE
    _VM_REFS_CACHE = {}


def vm_ref_cache_delete(id):
    _VM_REFS_CACHE.pop(id, None)


def vm_ref_cache_update(id, vm_ref):
    _VM_REFS_CACHE[id] = vm_ref


def vm_ref_cache_get(id):
    return _VM_REFS_CACHE.get(id)


def _vm_ref_cache(id, func, session, data):
    vm_ref = vm_ref_cache_get(id)
    if not vm_ref:
        vm_ref = func(session, data)
        vm_ref_cache_update(id, vm_ref)
    return vm_ref


def vm_ref_cache_from_instance(func):
    @functools.wraps(func)
    def wrapper(session, instance):
###        id = instance.uuid
        id = instance['uuid']
        return _vm_ref_cache(id, func, session, instance)
    return wrapper


def vm_ref_cache_from_name(func):
    @functools.wraps(func)
    def wrapper(session, name):
        id = name
        return _vm_ref_cache(id, func, session, name)
    return wrapper

# the config key which stores the VNC port
VNC_CONFIG_KEY = 'config.extraConfig["RemoteDisplay.vnc.port"]'

VmdkInfo = collections.namedtuple('VmdkInfo', ['path', 'adapter_type',
                                               'disk_type',
                                               'capacity_in_bytes',
                                               'device'])


def _iface_id_option_value(client_factory, iface_id, port_index):
    opt = client_factory.create('ns0:OptionValue')
    opt.key = "nvp.iface-id.%d" % port_index
    opt.value = iface_id
    return opt


def _get_allocation_info(client_factory, limits, allocation_type):
    allocation = client_factory.create(allocation_type)
    if limits.limit:
        allocation.limit = limits.limit
    else:
        # Set as 'umlimited'
        allocation.limit = -1
    if limits.reservation:
        allocation.reservation = limits.reservation
    else:
        allocation.reservation = 0
    shares = client_factory.create('ns0:SharesInfo')
    if limits.shares_level:
        shares.level = limits.shares_level
        if (shares.level == 'custom' and
            limits.shares_share):
            shares.shares = limits.shares_share
        else:
            shares.shares = 0
    else:
        shares.level = 'normal'
        shares.shares = 0
    # The VirtualEthernetCardResourceAllocation has 'share' instead of
    # 'shares'.
    if hasattr(allocation, 'share'):
        allocation.share = shares
    else:
        allocation.shares = shares
    return allocation


# Vsettan-only start
def is_windows(guest_id):
    return guest_id.startswith(constants.WIN_GUEST_PREFIX)

def get_child_element_by_tag_and_attribute_val(parent, tag_name, attr_name, attr_val):
    node_list = parent.getElementsByTagName(tag_name)
    if node_list is None:
        return None
    for each in node_list:
        if(each.hasAttribute(attr_name) and attr_val == each.getAttribute(attr_name)):
            return each
    return None

def get_child_element(elem, child_name):
    elems = elem.getElementsByTagName(child_name)
    if len(elems) == 0 :
        return None
    child_elem = elems[0]
    if child_elem.parentNode != elem :
        return None
    return child_elem

def get_CIDR(ip, subnet_mask):

    #eg cidr: '10.104.0.0/22'
    cidr = IP(ip).make_net(subnet_mask)

    list_elem = []
    list_elem.append(ip)

    #eg: '/24'
    list_elem.append(cidr._printPrefix(1))

    #eg:
    #return '10.104.0.222/24'
    ip_mask_in_CIDR = ''.join(list_elem)

    return ip_mask_in_CIDR

def build_interface(elem, metadata, adapter_name, interface_seq, is_dns_client, network_info):
    identifier_elem = elem.getElementsByTagName(constants.SYSPREP_IDENTIFIER)[0]
    if interface_seq < 2 :
        identifier_elem.childNodes[0].data = constants.SYSPREP_LOCAL_CONNECTION
    else :
        name = constants.SYSPREP_LOCAL_CONNECTION_D %interface_seq
        identifier_elem.childNodes[0].data = name

    adapter_index = filter(lambda x:x.isdigit(),adapter_name)
    i = int(adapter_index)-1

    if is_dns_client :
        #ip
        ip_elem = elem.getElementsByTagName(constants.SYSPREP_IP)[0]
        if network_info[i]['network']['subnets'][0]['dns']:
            ip_elem.childNodes[0].data = network_info[i]['network']['subnets'][0]['dns'][0]['address']

        dns_ip_addr = constants.METADATA_NETWORK_DNS % adapter_name
        if dns_ip_addr in metadata :
            ip_elem.childNodes[0].data = metadata[dns_ip_addr]

        #dns domain name (dns suffix)
        if constants.METADATA_DNS_SUF in metadata :
            domain_elem = elem.getElementsByTagName(constants.SYSPREP_DNS_DOMAIN)[0]
            domain_elem.childNodes[0].data = metadata[constants.METADATA_DNS_SUF]

    else :
        dhcp_elem = elem.getElementsByTagName(constants.SYSPREP_DHCP_ENABLED)[0]
        #dhcp need to be false, and it need to be string type in Document object rather than bool
        dhcp_elem.childNodes[0].data = 'false'

        #set interface ip
        #need to format ip and mask in CIDR
        ip_str = constants.METADATA_NETWORK_IP % adapter_name
        ip_subnetmask = constants.METADATA_NETWORK_MASK % adapter_name

        if network_info[i]['network']['subnets'][0]['ips'][0]['address']:
            ip_elem = elem.getElementsByTagName(constants.SYSPREP_IP)[0]
            subnet_ip = network_info[i]['network']['subnets'][0]['ips'][0]['address']
            subnet_cidr = network_info[i]['network']['subnets'][0]['cidr']
            mask_in_subnet = IP(subnet_cidr, make_net=True).strNetmask()
            ip_elem.childNodes[0].data = get_CIDR(subnet_ip, mask_in_subnet)

        if ip_str in metadata and ip_subnetmask in metadata:
            ip_elem = elem.getElementsByTagName(constants.SYSPREP_IP)[0]
            ip_elem.childNodes[0].data = get_CIDR(metadata[ip_str], metadata[ip_subnetmask])

        route_elem = get_child_element(elem, constants.SYSPREP_ROUTES)
        net_hop_elem = route_elem.getElementsByTagName(constants.SYSPREP_GATEWAY)[0]
        if network_info[i]['network']['subnets'][0]['gateway']['address']:
            net_hop_elem.childNodes[0].data = network_info[i]['network']['subnets'][0]['gateway']['address']

        gateway = constants.METADATA_NETWORK_GATEWAY % adapter_name
        if gateway in metadata :
            net_hop_elem.childNodes[0].data = metadata[gateway]

def build_specialize_interfaces(elem, metadata, adapter_names, is_dns_client, network_info):
    interfaces_elem = get_child_element(elem, constants.SYSPREP_INTERFACES)
    interface_elems = interfaces_elem.getElementsByTagName(constants.SYSPREP_INTERFACE)
    if interface_elems is None or len(interface_elems) < 1:
        msg = _('The input sysprep string is invalid since there is no interface element.')
        raise exception.Invalid(msg)

    num = 1
    handled_elem = interface_elems[0]
    if not adapter_names:
        adapter_names = []
        nic_num = len(network_info)
        for i in range(nic_num):
            adapter_name_fake = "%s%d" % ("adapter",(i+1))
            adapter_names.append(adapter_name_fake)
    for each in adapter_names :
        if num != 1 :
            handled_elem = interface_elems[0].cloneNode(True)
            interfaces_elem.appendChild(handled_elem)

        build_interface(handled_elem, metadata, each, num, is_dns_client, network_info)
        num = num + 1

def build_specialize_dns_client(dns_elem, metadata, adapter_names, network_info):
    build_specialize_interfaces(dns_elem, metadata, adapter_names, True, network_info)

def build_specialize_tcp_ip(tcp_ip_elem, metadata, adapter_names, network_info):
    build_specialize_interfaces(tcp_ip_elem, metadata, adapter_names, False, network_info)

def set_password(unattend_elem, metadata) :
    if constants.METADATA_PSWORD in metadata and metadata[constants.METADATA_PSWORD] is not None:
        password_elems = unattend_elem.getElementsByTagName(constants.SYSPREP_ADMIN_PSWORD)
        value_elems = password_elems[0].getElementsByTagName(constants.SYSPREP_VALUE)
        value_elems[0].childNodes[0].data = metadata[constants.METADATA_PSWORD]

def build_specialize_settings(unattend_elem, metadata, adapter_names, network_info):
    settings_elem = get_child_element_by_tag_and_attribute_val(unattend_elem,
                                                               constants.SYSPREP_SETTINGS,
                                                               constants.SYSPREP_PASS,
                                                               constants.SYSPREP_SPECIALIZE)
    tcp_ip_elem = get_child_element_by_tag_and_attribute_val(settings_elem,
                                                             constants.SYSPREP_COMP,
                                                             constants.SYSPREP_NAME,
                                                             constants.SYSPREP_TCPIP)
    dns_elem = get_child_element_by_tag_and_attribute_val(settings_elem,
                                                          constants.SYSPREP_COMP,
                                                          constants.SYSPREP_NAME,
                                                          constants.SYSPREP_DNS_CLIENT)

    #componentTcpIpElement
    build_specialize_tcp_ip(tcp_ip_elem, metadata, adapter_names, network_info)

    #componentDnsElement
    build_specialize_dns_client(dns_elem, metadata, adapter_names, network_info)

    #set password
    set_password(unattend_elem, metadata)

def get_user_data(instance, adapter_names, network_info):

    try :
        #parse user-data
        user_data_str = base64.b64decode(instance.user_data)
        dom = minidom.parseString(user_data_str)

        #update user-data
        unattend_elem = dom.getElementsByTagName(constants.SYSPREP_UNATTEN)[0]
        build_specialize_settings(unattend_elem, instance.metadata, adapter_names, network_info)

        return unattend_elem
    except Exception, e:
       LOG.error(_("Failed to get_user_data for CustomizationSysprepText." + str(e)))
       traceback.print_exc()

def get_first_dns_suffix_from_xml(unattend_elem) :
    dns_suffix_elem = unattend_elem.getElementsByTagName(constants.SYSPREP_DNS_DOMAIN)[0]
    return dns_suffix_elem.childNodes[0].data

def get_change_sid(metadata):
    change_sid = True
    chang_sid_key = constants.METADATA_WIN_OPTIONS_CHANGE_SID
    if chang_sid_key in metadata and metadata[chang_sid_key] is not None :
        if metadata[chang_sid_key] is constants.METADATA_VALUE_FALSE :
            LOG.warn(_("change sid will use the value: false"))
            change_sid = False
        else :
            LOG.warn(_("change sid will use the value: true"))

    return change_sid

def fill_adapter_mappings(client_factory, instance, adapter_names_in_metadata, unattend_elem, network_info):
    adapter_mappings = []
    nic_num = len(network_info)
    for i in range(nic_num):
        if network_info[i]['network']['subnets'][0]['dns']:
            adapter_mapping = client_factory.create('ns0:CustomizationAdapterMapping')
            adapter_info = client_factory.create('ns0:CustomizationIPSettings')

            #netmask, ip
            cidr = network_info[i]['network']['subnets'][0]['cidr']
            mask = IP(cidr, make_net=True).strNetmask()
            adapter_info.subnetMask = mask

            customization_fixed_ip = client_factory.create('ns0:CustomizationFixedIp')
            customization_fixed_ip.ipAddress = network_info[i]['network']['subnets'][0]['ips'][0]['address']
            adapter_info.ip = customization_fixed_ip

            #gateways
            gateways = []
            gateway = network_info[i]['network']['subnets'][0]['gateway']['address']
            gateways.append(gateway)
            adapter_info.gateway = gateways

            #dns servers
            dns_servers = []
            dns_server = network_info[i]['network']['subnets'][0]['dns'][0]['address']
            dns_servers.append(dns_server)
            adapter_info.dnsServerList = dns_servers

            adapter_mapping.adapter = adapter_info
            adapter_mappings.append(adapter_mapping)
        else:
            LOG.info(_("fill_adapter_mappings with xml: %s") % unattend_elem)
            #get the first adapter info (ip, mask, gateway, dns) from xml
            adapter_mapping = client_factory.create('ns0:CustomizationAdapterMapping')
            adapter_info = client_factory.create('ns0:CustomizationIPSettings')
            #ip and subnet mask
            customization_fixed_ip = client_factory.create('ns0:CustomizationFixedIp')
            unicast_ip_elem = unattend_elem.getElementsByTagName(constants.SYSPREP_UNICAST_IP)[0]
            ip_elem = unicast_ip_elem.getElementsByTagName(constants.SYSPREP_IP)[0]
            ip_mask_CIDR = ip_elem.childNodes[0].data
            ip_mask = ip_mask_CIDR.split("/", 2)
            ip = ip_mask[0]
            mask = IP(ip_mask_CIDR, make_net=True).strNetmask()
            adapter_info.subnetMask = mask
            customization_fixed_ip.ipAddress = ip
            adapter_info.ip = customization_fixed_ip
            #gateway
            gateways = []
            net_hop_elem = unattend_elem.getElementsByTagName(constants.SYSPREP_GATEWAY)[0]
            gateways.append(net_hop_elem.childNodes[0].data)
            adapter_info.gateway = gateways
            #dns
            dns_servers = []
            dns_server_elem = unattend_elem.getElementsByTagName(constants.SYSPREP_DNS_SEARCH)[0]
            dns_ip_elem = dns_server_elem.getElementsByTagName(constants.SYSPREP_IP)[0]
            dns_servers.append(dns_ip_elem.childNodes[0].data)
            adapter_info.dnsServerList = dns_servers
            
            adapter_mapping.adapter = adapter_info
            adapter_mappings.append(adapter_mapping)
    if adapter_names_in_metadata is not None and len(adapter_names_in_metadata) >= 1 :
        LOG.info(_("fill_adapter_mappings with metadata is: %s") % adapter_names_in_metadata)
        adapter_mappings = []
        for each_adapter in adapter_names_in_metadata:
            adapter_mapping = client_factory.create('ns0:CustomizationAdapterMapping')
            adapter_info = client_factory.create('ns0:CustomizationIPSettings')

            #netmask, ip
            adapter_netmask_key = constants.METADATA_NETWORK_MASK % each_adapter
            adapter_info.subnetMask = instance.metadata[adapter_netmask_key]

            customization_fixed_ip = client_factory.create('ns0:CustomizationFixedIp')
            adapter_addr_key = constants.METADATA_NETWORK_IP % each_adapter
            customization_fixed_ip.ipAddress = instance.metadata[adapter_addr_key]
            adapter_info.ip = customization_fixed_ip

            #gateways
            gateways = []
            #echo adapter need one gateway at least
            adapter_gw_key = constants.METADATA_NETWORK_GATEWAY % each_adapter
            gateways.append(instance.metadata[adapter_gw_key])
            adapter_gw_key2 = constants.METADATA_NETWORK_GATEWAY2 % each_adapter
            if adapter_gw_key2 in instance.metadata :
                gateways.append(instance.metadata[adapter_gw_key2])
            adapter_info.gateway = gateways

            #dns servers
            dns_servers = []
            dns_key = constants.METADATA_NETWORK_DNS % each_adapter
            dns_servers.append(instance.metadata[dns_key])
            dns_key2 = constants.METADATA_NETWORK_DNS2 % each_adapter
            if dns_key2 in instance.metadata :
                dns_servers.append(instance.metadata[dns_key2])
            adapter_info.dnsServerList = dns_servers

            #primaryWINS and secondaryWINS
            #pri_wins = "networkdevice.%s.primaryWINS" % each_adapter
            #sec_wins = "networkdevice.%s.secondaryWINS" % each_adapter
            #adapter_info.primaryWINS = instance.metadata[pri_wins]
            #adapter_info.secondaryWINS = instance.metadata[sec_wins]

            adapter_mapping.adapter = adapter_info

            adapter_mappings.append(adapter_mapping)

    return adapter_mappings

def get_global_ip_settings(client_factory, instance, user_data_sysprep_xml):
    global_ip_settings = client_factory.create('ns0:CustomizationGlobalIPSettings')

    #Need the dns.suffix to avoid globalIPSettings invalid exception
    dns_suffix_list = []
    if constants.METADATA_DNS_SUF in instance.metadata:
        dns_suffix_list.append(instance.metadata[constants.METADATA_DNS_SUF])
        LOG.info(_("dns_suffix from metadata is: %s") % instance.metadata[constants.METADATA_DNS_SUF])
    elif user_data_sysprep_xml is not None :
        #use the first dns.suffix in the xml, if no metadata for dns.suffix
        dns_suffix = get_first_dns_suffix_from_xml(user_data_sysprep_xml)
        dns_suffix_list.append(dns_suffix)
        LOG.info(_("dns_suffix from xml is: %s") % dns_suffix)
    else :
        dns_suffix_list.append(CONF.vmware.dns_suffix)
        LOG.info(_("dns_suffix from conf file is: %s") % dns_suffix_list)
    global_ip_settings.dnsSuffixList = dns_suffix_list
    return  global_ip_settings

def get_vm_cust_spec_for_windows_sysprep_text(client_factory, instance, network_info):

    LOG.info(_LI("get_vm_cust_spec_for_windows_sysprep_text entry"), instance=instance)

    adapter_names_in_metadata = []

    #check the parameters
    if (instance.user_data is None):
        msg = _('user_data should be provided for CustomizationSysprepText')
        raise exception.Invalid(msg)

    for each in instance.metadata:
        if each.startswith(constants.METADATA_NETWORK_PREFIX) and each.endswith(constants.METADATA_NETWORK_IP_SUFFIX):
            adapter_name = each.split(".", 2)[1]
            adapter_names_in_metadata.append(adapter_name)
            adapter_gateway = constants.METADATA_NETWORK_GATEWAY % adapter_name
            LOG.warn(_("IP, gateway, dns and netmask need to be provided together, if the adapter is specified in metadata"))
            #Although provide the value for pri_wins and sec_wins, the value are not assigned to syspreptext.
            #VM just take the value of syspreptext
            #
            #pri_wins = "networkdevice.%s.primaryWINS" % adapter_name
            #if pri_wins not in instance.metadata:
            #    msg = _('%s should be provided for the adapter in instance metadata.') % pri_wins
            #    raise exception.Invalid(msg)
            #sec_wins = "networkdevice.%s.secondaryWINS" % adapter_name
            #if sec_wins not in instance.metadata:
            #    msg = _('%s should be provided for the adapter in instance metadata.') % sec_wins
            #    raise exception.Invalid(msg)

    LOG.debug(_("cust_spec network_info: %s") % network_info)
    #Note that the nic numbers need to match the networks numbers which users spawn
    if len(adapter_names_in_metadata) >=1 and len(adapter_names_in_metadata) != len(network_info):
        #adapter number in metadata should be match the nic in network_info, if we provide the adapter(>=1) in metadata.
        #If we do not provide the adapter(=0) in metadata, the code will use the adapter info in xml
        msg = _('The adapters number (%s) should match network_info, when provide adapter info via medadata') % adapter_names_in_metadata
        raise exception.Invalid(msg)

    #identity
    adapter_names_in_metadata = sorted(adapter_names_in_metadata)
    user_data_sysprep_xml = get_user_data(instance, adapter_names_in_metadata, network_info)
    if user_data_sysprep_xml is None :
        msg = _("parse the xml and return None for it, Please double-check the specified xml file")
        raise exception.Invalid(msg)

    cust_spec = client_factory.create('ns0:CustomizationSpec')
    identity_info = client_factory.create('ns0:CustomizationSysprepText')
    identity_info.value = encodeutils.safe_encode(user_data_sysprep_xml.toxml())
    cust_spec.identity = identity_info
    LOG.debug(_("cust_spec identity_info: %s") % cust_spec.identity)

    #globalIPSettings
    cust_spec.globalIPSettings = get_global_ip_settings(client_factory,
                                                        instance,
                                                        user_data_sysprep_xml)
    LOG.debug(_("cust_spec globalIPSettings: %s") % cust_spec.globalIPSettings)

    #nicSettingMap
    #Note that the nic numbers need to match the networks numbers which users spawn
    cust_spec.nicSettingMap = fill_adapter_mappings(client_factory,
                                                    instance,
                                                    adapter_names_in_metadata,
                                                    user_data_sysprep_xml,
                                                    network_info)
    LOG.debug(_("cust_spec nicSettingMap: %s") % cust_spec.nicSettingMap)
    if len(cust_spec.nicSettingMap) != len(network_info):
        msg = _('The adapters number (%s) should match network_info') % cust_spec.nicSettingMap
        raise exception.Invalid(msg)

    #options
    options = client_factory.create('ns0:CustomizationWinOptions')
    options.changeSID = get_change_sid(instance.metadata)
    options.deleteAccounts = False
    cust_spec.options = options

    LOG.debug(_("cust_spec cust_spec: %s") % cust_spec)
    LOG.info(_LI("get_vm_cust_spec_for_windows_sysprep_text exit"), instance=instance)
    return cust_spec

def get_vm_cust_spec_for_linux(client_factory, instance, network_info):
    adapter_name_set = set()
    for each in instance.metadata:
        if each.startswith("networkdevice") and each.endswith("ipaddress"):
            adapter_name = each.split(".", 2)[1]
            adapter_name_set.add(adapter_name)
            adapter_netmask_name = "networkdevice.%s.netmask" % adapter_name
            if adapter_netmask_name not in instance.metadata:
                msg = _('%s should be provided for the adapter in instance metadata.') % adapter_netmask_name
                raise exception.Invalid(msg)

    if not adapter_name_set:
        cust_spec = client_factory.create('ns0:CustomizationSpec')
        identity_info = client_factory.create('ns0:CustomizationLinuxPrep')
        #domainname
        if 'linux.domainname' in instance.metadata:
            identity_info.domain = instance.metadata['linux.domainname']
        else:
            identity_info.domain = CONF.vmware.domain_name
        #hostname
        hostName_info = client_factory.create('ns0:CustomizationFixedName')
        if 'linux.hostname' in instance.metadata:
            hostName_info.name = instance.metadata['linux.hostname']
        else:
            hostName_info.name = instance.display_name
        identity_info.hostName = hostName_info
        cust_spec.identity = identity_info

        adapter_mappings = []
        nic_num = len(network_info)
        for i in range(nic_num):
            adapter_mapping = client_factory.create('ns0:CustomizationAdapterMapping')
            adapter_info = client_factory.create('ns0:CustomizationIPSettings')
            CustomizationFixedIp_info = client_factory.create('ns0:CustomizationFixedIp')

            CustomizationFixedIp_info.ipAddress = network_info[i]['network']['subnets'][0]['ips'][0]['address']
            adapter_info.ip = CustomizationFixedIp_info

            adapter_info.gateway = [network_info[i]['network']['subnets'][0]['gateway']['address']]
            #Get the netmask
            subnet_cidr = network_info[i]['network']['subnets'][0]['cidr']
            mask_in_subnet = IP(subnet_cidr, make_net=True).strNetmask()
            adapter_info.subnetMask = mask_in_subnet

            #Get the dnsdomain
            if 'linux.dnsdomain' in instance.metadata:
                adapter_info.dnsDomain = instance.metadata['linux.dnsdomain']
            adapter_mapping.adapter = adapter_info
            adapter_mappings.append(adapter_mapping)

        globalIPSettings_info = client_factory.create('ns0:CustomizationGlobalIPSettings')
        dns_server_list = []
        for i in range(nic_num):
            if network_info[i]['network']['subnets'][0]['dns']:
                for index in range(len(network_info[i]['network']['subnets'][0]['dns'])):
                    dns_nameserver = network_info[i]['network']['subnets'][0]['dns'][index]['address']
                    dns_server_list.append(dns_nameserver)
        globalIPSettings_info.dnsServerList = dns_server_list

        dns_suffix_list = []
        if 'dns.suffix' in instance.metadata:
            dns_suffix_list.append(instance.metadata['dns.suffix'])
        else:
            dns_suffix = CONF.vmware.dns_suffix
            dns_suffix_list.append(dns_suffix)
        globalIPSettings_info.dnsSuffixList = dns_suffix_list
        cust_spec.globalIPSettings = globalIPSettings_info
        cust_spec.nicSettingMap = adapter_mappings
        return cust_spec

    if len(adapter_name_set) != len(network_info):
        msg = _('The number of adapters does not match that of the network provided.')
        raise exception.Invalid(msg)

    cust_spec = client_factory.create('ns0:CustomizationSpec')

    # Do not support Windows
    identity_info = client_factory.create('ns0:CustomizationLinuxPrep')
    identity_info.domain = 'linux.domainname'
    if 'linux.domainname' in instance.metadata:
        identity_info.domain = instance.metadata['linux.domainname']
    #Get the hostname
    hostName_info = client_factory.create('ns0:CustomizationFixedName')
    if 'linux.hostname' in instance.metadata:
        hostName_info.name = instance.metadata['linux.hostname']
    else:
        hostName_info.name = instance.display_name
    identity_info.hostName = hostName_info
    cust_spec.identity = identity_info

    adapter_mappings = []
    # As instance.metadata may not strictly get ordered, need to ensure the nic orders correspond to networks orders.
    adapter_name_set = sorted(adapter_name_set)
    for each_adapter in adapter_name_set:
        adapter_mapping = client_factory.create('ns0:CustomizationAdapterMapping')
        adapter_info = client_factory.create('ns0:CustomizationIPSettings')
        CustomizationFixedIp_info = client_factory.create('ns0:CustomizationFixedIp')

        adapter_addr_key = "networkdevice.%s.ipaddress" % each_adapter
        CustomizationFixedIp_info.ipAddress = instance.metadata[adapter_addr_key]
        adapter_info.ip = CustomizationFixedIp_info

        adapter_gw_key = "networkdevice.%s.gateway1" % each_adapter
        adapter_info.gateway = [instance.metadata[adapter_gw_key]]

        adapter_netmask_key = "networkdevice.%s.netmask" % each_adapter
        adapter_info.subnetMask = instance.metadata[adapter_netmask_key]

        if 'linux.dnsdomain' in instance.metadata:
            adapter_info.dnsDomain = instance.metadata['linux.dnsdomain']
        adapter_mapping.adapter = adapter_info

        adapter_mappings.append(adapter_mapping)

    globalIPSettings_info = client_factory.create('ns0:CustomizationGlobalIPSettings')

    dns_server_list = []
    for each in ['linux.dns1', 'linux.dns2']:
        if each in instance.metadata:
            dns_server_list.append(instance.metadata[each])
    globalIPSettings_info.dnsServerList = dns_server_list

    dns_suffix_list = []
    if 'dns.suffix' in instance.metadata:
        dns_suffix_list.append(instance.metadata['dns.suffix'])
    globalIPSettings_info.dnsSuffixList = dns_suffix_list

    cust_spec.globalIPSettings = globalIPSettings_info

    cust_spec.nicSettingMap = adapter_mappings
    LOG.debug('cust spec in meta is %s', cust_spec)
    return cust_spec

def get_adapters_info_from_network(network_info):
    adapters_name = []
    adapters_info = {}

    LOG.debug(_("cust_spec get adatper network_info: %s") % network_info)
    nic_num = len(network_info)
    for i in range(nic_num):
        if network_info[i]['network']['subnets'][0]['dns']:
            adapter_name = i + 1
            adapters_name.append(adapter_name)

            adapter_netmask_key = constants.METADATA_NETWORK_MASK % adapter_name
            adapter_gateway_key = constants.METADATA_NETWORK_GATEWAY % adapter_name
            adapter_dns_key = constants.METADATA_NETWORK_DNS % adapter_name
            adapter_dns_key2 = constants.METADATA_NETWORK_DNS2 % adapter_name
            adapter_ip_key = constants.METADATA_NETWORK_IP % adapter_name

            cidr = network_info[i]['network']['subnets'][0]['cidr']
            mask = IP(cidr, make_net=True).strNetmask()

            adapters_info[adapter_netmask_key] = mask
            adapters_info[adapter_ip_key] = network_info[i]['network']['subnets'][0]['ips'][0]['address']

            adapters_info[adapter_gateway_key] = network_info[i]['network']['subnets'][0]['gateway']['address']

            adapters_info[adapter_dns_key] = network_info[i]['network']['subnets'][0]['dns'][0]['address']
            if len(network_info[i]['network']['subnets'][0]['dns']) > 1 :
                 adapters_info[adapter_dns_key2] = network_info[i]['network']['subnets'][0]['dns'][1]['address']

    LOG.debug(_("cust_spec get adapters_name: %s") % adapters_name)
    return (adapters_name, adapters_info)

def get_adapters_name_from_metadata(instance):
    adapter_names_in_metadata = []
    #check the parameters
    for each in instance.metadata:
        if each.startswith(constants.METADATA_NETWORK_PREFIX) and each.endswith(constants.METADATA_NETWORK_IP_SUFFIX):
            adapter_name = each.split(".", 2)[1]
            adapter_names_in_metadata.append(adapter_name)
            adapter_gateway = constants.METADATA_NETWORK_GATEWAY % adapter_name
            LOG.warn(_("IP, gateway, dns and netmask need to be provided together, if the adapter is specified in metadata"))
            if adapter_gateway not in instance.metadata or instance.metadata[adapter_gateway] is None:
                msg = _('%s should be provided for the adapter in instance metadata.') % adapter_gateway
                raise exception.Invalid(msg)
            adapter_dns = constants.METADATA_NETWORK_DNS % adapter_name
            if adapter_dns not in instance.metadata  or instance.metadata[adapter_dns] is None:
                msg = _('%s should be provided for the adapter in instance metadata.') % adapter_dns
                raise exception.Invalid(msg)
            adapter_netmask = constants.METADATA_NETWORK_MASK % adapter_name
            if adapter_netmask not in instance.metadata  or instance.metadata[adapter_netmask] is None:
                msg = _('%s should be provided for the adapter in instance metadata.') % adapter_netmask
                raise exception.Invalid(msg)
    return adapter_names_in_metadata

def fill_adapter_mappings_list(client_factory, data_from_metadata_or_network, adapter_names):
    adapter_mappings = []
    if adapter_names is not None and len(adapter_names) >= 1 :
        LOG.info(_("fill_adapter_mappings_list with names: %s") % adapter_names)
        LOG.info(_("fill_adapter_mappings_list with adapters: %s") % data_from_metadata_or_network)
        for each_adapter in adapter_names:
            adapter_mapping = client_factory.create('ns0:CustomizationAdapterMapping')
            adapter_info = client_factory.create('ns0:CustomizationIPSettings')

            #netmask, ip
            adapter_netmask_key = constants.METADATA_NETWORK_MASK % each_adapter
            adapter_info.subnetMask = data_from_metadata_or_network[adapter_netmask_key]

            customization_fixed_ip = client_factory.create('ns0:CustomizationFixedIp')
            adapter_addr_key = constants.METADATA_NETWORK_IP % each_adapter
            customization_fixed_ip.ipAddress = data_from_metadata_or_network[adapter_addr_key]
            adapter_info.ip = customization_fixed_ip

            #gateways
            gateways = []
            #echo adapter need one gateway at least
            adapter_gw_key = constants.METADATA_NETWORK_GATEWAY % each_adapter
            gateways.append(data_from_metadata_or_network[adapter_gw_key])
            adapter_gw_key2 = constants.METADATA_NETWORK_GATEWAY2 % each_adapter
            if adapter_gw_key2 in data_from_metadata_or_network:
                gateways.append(data_from_metadata_or_network[adapter_gw_key2])

            adapter_info.gateway = gateways

            #dns servers
            dns_servers = []
            dns_key = constants.METADATA_NETWORK_DNS % each_adapter
            dns_servers.append(data_from_metadata_or_network[dns_key])
            dns_key2 = constants.METADATA_NETWORK_DNS2 % each_adapter
            if dns_key2 in data_from_metadata_or_network :
                dns_servers.append(data_from_metadata_or_network[dns_key2])
            adapter_info.dnsServerList = dns_servers

            #primaryWINS and secondaryWINS
            pri_wins_key = constants.METADATA_WIN_PRI_WINS % each_adapter
            if pri_wins_key in data_from_metadata_or_network :
                adapter_info.primaryWINS = data_from_metadata_or_network[pri_wins_key]

                sec_wins_key = constants.METADATA_WIN_SEC_WINS % each_adapter
                if sec_wins_key in data_from_metadata_or_network :
                    adapter_info.secondaryWINS = data_from_metadata_or_network[sec_wins_key]

            adapter_mapping.adapter = adapter_info

            adapter_mappings.append(adapter_mapping)

    return adapter_mappings

def fill_gui_unatteneded(client_factory, metadata):
    guiUnattended_info = client_factory.create('ns0:CustomizationGuiUnattended')
    guiUnattended_info.autoLogon = False
    guiUnattended_info.autoLogonCount = 0

    password_info = None
    if constants.METADATA_PSWORD in metadata and len(metadata[constants.METADATA_PSWORD]) > 0 :
        password_info = client_factory.create('ns0:CustomizationPassword')
        password_info.plainText = True
        password_info.value = metadata[constants.METADATA_PSWORD]

    guiUnattended_info.password = password_info

    if constants.METADATA_TIME_ZONE in metadata :
        int_value = CONF.vmware.timezone
        try:
           int_value = int(metadata[constants.METADATA_TIME_ZONE])
        except Exception as exce:
           int_value = CONF.vmware.timezone
        guiUnattended_info.timeZone = int_value
    else :
        guiUnattended_info.timeZone = CONF.vmware.timezone

    return guiUnattended_info

def fill_identification(client_factory, metadata):
    identification_info = client_factory.create('ns0:CustomizationIdentification')
    if constants.METADATA_WIN_WORKGOURP in metadata :
        identification_info.joinWorkgroup = metadata[constants.METADATA_WIN_WORKGOURP]
    elif constants.METADATA_WIN_DOMAINNAME in metadata and constants.METADATA_WIN_DOMAIN_USER in metadata:
        identification_info.joinDomain = metadata[constants.METADATA_WIN_DOMAINNAME]
        identification_info.domainAdmin = metadata[constants.METADATA_WIN_DOMAIN_USER]
        password_info = None
        if constants.METADATA_WIN_DOMAIN_PSWORD in metadata :
            password_info = client_factory.create('ns0:CustomizationPassword')
            password_info.plainText = True
            password_info.value = metadata[constants.METADATA_WIN_DOMAIN_PSWORD]
        identification_info.domainAdminPassword = password_info
    else :
        identification_info.joinWorkgroup = CONF.vmware.workgroup
    return identification_info

def fill_userData(client_factory, metadata, inst_name):
    userData_info = client_factory.create('ns0:CustomizationUserData')
    fixedName_info = client_factory.create('ns0:CustomizationFixedName')
    if constants.METADATA_WIN_COMPUTER_NAME in metadata :
        fixedName_info.name = metadata[constants.METADATA_WIN_COMPUTER_NAME]
    else :
        fixedName_info.name = inst_name
    userData_info.computerName = fixedName_info

    if constants.METADATA_WIN_ORGANIZATION in metadata :
        userData_info.orgName = metadata[constants.METADATA_WIN_ORGANIZATION]
    else :
        userData_info.orgName = CONF.vmware.organization_name
    if constants.METADATA_WIN_PRODUCTKEY in metadata :
        userData_info.productId = metadata[constants.METADATA_WIN_PRODUCTKEY]
    else :
        userData_info.productId = CONF.vmware.product_key
    if constants.METADATA_WIN_USERNAME in metadata :
        userData_info.fullName = metadata[constants.METADATA_WIN_USERNAME]
    else :
        userData_info.fullName = CONF.vmware.user_name

    return userData_info

def fill_identity_for_windows_sysprep(client_factory, instance):
    #identity
    identity_info = client_factory.create('ns0:CustomizationSysprep')
    identity_info.guiUnattended = fill_gui_unatteneded(client_factory, instance.metadata)
    identity_info.identification = fill_identification(client_factory, instance.metadata)
    identity_info.userData = fill_userData(client_factory, instance.metadata, instance.display_name)

    return identity_info

def get_vm_cust_spec_for_windows_sysprep(client_factory, instance, network_info):
    LOG.info(_LI("get_vm_cust_spec_for_windows_sysprep entry"), instance=instance)

    adapters_name_in_metadata = get_adapters_name_from_metadata(instance)
    LOG.debug(_("Metadata adapters_name_in_metadata: %s") % adapters_name_in_metadata)

    LOG.debug(_("cust_spec network_info: %s") % network_info)
    #Note that the nic numbers need to match the networks numbers which users spawn
    if len(adapters_name_in_metadata) >=1 and len(adapters_name_in_metadata) != len(network_info):
        #adapter number in metadata should be match the nic in network_info, if we provide the adapter(>=1) in metadata.
        #If we do not provide the adapter(=0) in metadata, the code will use the adapter info in xml
        msg = _('The adapters number (%s) should match network_info, when provide adapter info via medadata') % adapters_name_in_metadata
        raise exception.Invalid(msg)

    #use adapter info in metadata, if adapter info exists in metadata, or use the info in network
    adapters_name = None
    adapters_info = None
    if len(adapters_name_in_metadata) >= 1 :
        adapters_name = adapters_name_in_metadata
        adapters_info = instance.metadata
        LOG.debug(_("Use metadata: %s ,rather than adapters info in network") % adapters_info)
    else :
        #get adapter info from network_info
        adapters_name, adapters_info = get_adapters_info_from_network(network_info)
        LOG.debug(_("Use Network adapters_info: %s") % adapters_info)

    cust_spec = client_factory.create('ns0:CustomizationSpec')

    #identity
    cust_spec.identity = fill_identity_for_windows_sysprep(client_factory,
                                                           instance)
    LOG.debug(_("cust_spec identity_info: %s") % cust_spec.identity)

    #globalIPSettings
    cust_spec.globalIPSettings = get_global_ip_settings(client_factory,
                                                        instance,
                                                        None)
    LOG.debug(_("cust_spec globalIPSettings: %s") % cust_spec.globalIPSettings)

    #nicSettingMap
    cust_spec.nicSettingMap = fill_adapter_mappings_list(client_factory,
                                                    adapters_info,
                                                    adapters_name)
    LOG.debug(_("cust_spec nicSettingMap: %s") % cust_spec.nicSettingMap)
    if len(cust_spec.nicSettingMap) != len(network_info):
        msg = _('The adapters number (%s) should match network_info') % cust_spec.nicSettingMap
        raise exception.Invalid(msg)

    #options
    options = client_factory.create('ns0:CustomizationWinOptions')
    options.changeSID = get_change_sid(instance.metadata)
    options.deleteAccounts = False
    cust_spec.options = options

    LOG.debug(_("windows_sysprep cust_spec: %s") % cust_spec)
    LOG.info(_LI("get_vm_cust_spec_for_windows_sysprep exit"), instance=instance)
    return cust_spec

def get_vm_cust_spec(client_factory, instance, network_info, guest_id):
    LOG.info(_LI("get_vm_cust_spec"), instance=instance)
    if is_windows(guest_id) :
        if instance.user_data is None :
            return get_vm_cust_spec_for_windows_sysprep(client_factory, instance, network_info)
        else :
            return get_vm_cust_spec_for_windows_sysprep_text(client_factory, instance, network_info)
    else :
        return get_vm_cust_spec_for_linux(client_factory, instance, network_info)
# Vsettan-only end


def get_vm_create_spec(client_factory, instance, name, #Vsettan-only
                       data_store_name,
                       vif_infos, extra_specs,
                       os_type=constants.DEFAULT_OS_TYPE,
                       profile_spec=None,
                       metadata=None,
                       ds_ref=None):#Vsettan-only
    """Builds the VM Create spec."""
    config_spec = client_factory.create('ns0:VirtualMachineConfigSpec')
    config_spec.name = name
    config_spec.guestId = os_type
    # The name is the unique identifier for the VM. This will either be the
    # instance UUID or the instance UUID with suffix '-rescue' for VM's that
    # are in rescue mode
    config_spec.instanceUuid = instance.uuid
    # set the Hardware version
    config_spec.version = extra_specs.hw_version

    # Allow nested hypervisor instances to host 64 bit VMs.
    if os_type in ("vmkernel5Guest", "vmkernel6Guest", "windowsHyperVGuest"):
        config_spec.nestedHVEnabled = "True"

    # Append the profile spec
    if profile_spec:
        config_spec.vmProfile = [profile_spec]

    vm_file_info = client_factory.create('ns0:VirtualMachineFileInfo')
    vm_file_info.vmPathName = "[" + data_store_name + "]"
    config_spec.files = vm_file_info

    tools_info = client_factory.create('ns0:ToolsConfigInfo')
    tools_info.afterPowerOn = True
    tools_info.afterResume = True
    tools_info.beforeGuestStandby = True
    tools_info.beforeGuestShutdown = True
    tools_info.beforeGuestReboot = True

    config_spec.tools = tools_info
    config_spec.numCPUs = int(instance.vcpus)
    if extra_specs.cores_per_socket:
        config_spec.numCoresPerSocket = int(extra_specs.cores_per_socket)
    config_spec.memoryMB = int(instance.memory_mb)

    # Configure cpu information
    if extra_specs.cpu_limits.has_limits():
        config_spec.cpuAllocation = _get_allocation_info(
            client_factory, extra_specs.cpu_limits,
            'ns0:ResourceAllocationInfo')

    # Configure memory information
    if extra_specs.memory_limits.has_limits():
        config_spec.memoryAllocation = _get_allocation_info(
            client_factory, extra_specs.memory_limits,
            'ns0:ResourceAllocationInfo')

    # Vsettan-only begin hot resize
    # Enable cpu/memory hot add feature when create new VM, so that they can
    # support hot resize. Need an config option here?
    config_spec.cpuHotAddEnabled = True
    config_spec.cpuHotRemoveEnabled = True
    config_spec.memoryHotAddEnabled = True
    # Vsettan-only stop hot resized

    devices = []
    for vif_info in vif_infos:
        vif_spec = _create_vif_spec(client_factory, vif_info,
                                    extra_specs.vif_limits)
        devices.append(vif_spec)

    serial_port_spec = create_serial_port_spec(client_factory)
    if serial_port_spec:
        devices.append(serial_port_spec)

    config_spec.deviceChange = devices

    # add vm-uuid and iface-id.x values for Neutron
    extra_config = []
    opt = client_factory.create('ns0:OptionValue')
    opt.key = "nvp.vm-uuid"
    opt.value = instance.uuid
    extra_config.append(opt)

    # Vsettan-only start
    # replace the serial log file when the instance is restarted
    opt = client_factory.create('ns0:OptionValue')
    opt.key = "answer.msg.serial.file.open"
    opt.value = "Replace"
    extra_config.append(opt)
    # Vsettan-only end

    port_index = 0
    for vif_info in vif_infos:
        if vif_info['iface_id']:
            extra_config.append(_iface_id_option_value(client_factory,
                                                       vif_info['iface_id'],
                                                       port_index))
            port_index += 1

    if (CONF.vmware.console_delay_seconds and
            CONF.vmware.console_delay_seconds > 0):
        opt = client_factory.create('ns0:OptionValue')
        opt.key = 'keyboard.typematicMinDelay'
        opt.value = CONF.vmware.console_delay_seconds * 1000000
        extra_config.append(opt)

    config_spec.extraConfig = extra_config

    # Set the VM to be 'managed' by 'OpenStack'
    managed_by = client_factory.create('ns0:ManagedByInfo')
    managed_by.extensionKey = constants.EXTENSION_KEY
    managed_by.type = constants.EXTENSION_TYPE_INSTANCE
    config_spec.managedBy = managed_by

    return config_spec


def create_serial_port_spec(client_factory):
    """Creates config spec for serial port."""
    if not CONF.vmware.serial_port_service_uri:
        return

    backing = client_factory.create('ns0:VirtualSerialPortURIBackingInfo')
    backing.direction = "server"
    backing.serviceURI = CONF.vmware.serial_port_service_uri
    backing.proxyURI = CONF.vmware.serial_port_proxy_uri
###    backing = client_factory.create('ns0:VirtualSerialPortFileBackingInfo')
###    backing.datastore = ds_ref
###    console_filename = "[%s] %s/%s" % (ds_name, instance_uuid, "console.log")
###    backing.fileName = console_filename

    connectable_spec = client_factory.create('ns0:VirtualDeviceConnectInfo')
    connectable_spec.startConnected = True
    connectable_spec.allowGuestControl = True
    connectable_spec.connected = True

    serial_port = client_factory.create('ns0:VirtualSerialPort')
    serial_port.connectable = connectable_spec
    serial_port.backing = backing
    # we are using unique negative integers as temporary keys
    serial_port.key = -2
    serial_port.yieldOnPoll = True
    dev_spec = client_factory.create('ns0:VirtualDeviceConfigSpec')
    dev_spec.operation = "add"
    dev_spec.device = serial_port
    return dev_spec


def get_vm_boot_spec(client_factory, device):
    """Returns updated boot settings for the instance.

    The boot order for the instance will be changed to have the
    input device as the boot disk.
    """
    config_spec = client_factory.create('ns0:VirtualMachineConfigSpec')
    boot_disk = client_factory.create(
        'ns0:VirtualMachineBootOptionsBootableDiskDevice')
    boot_disk.deviceKey = device.key
    boot_options = client_factory.create('ns0:VirtualMachineBootOptions')
    boot_options.bootOrder = [boot_disk]
    config_spec.bootOptions = boot_options
    return config_spec


# Vsettan-only (prs-related) begin
def get_serial_port_device(session, vm_ref):
    """Get serial port device"""
    hardware_devices = session._call_method(vim_util,
                       "get_dynamic_property", vm_ref,
                       "VirtualMachine", "config.hardware.device")

    if hardware_devices.__class__.__name__ == "ArrayOfVirtualDevice":
        virtual_devices = hardware_devices.VirtualDevice

    for device in virtual_devices:
        if (device.__class__.__name__ == "VirtualSerialPort"):
            return device
    return None

def get_disconnect_serial_port_spec(client_factory, device):
    """Disconnect serial port device if needed"""
    if client_factory and device:
        config_spec = client_factory.create('ns0:VirtualMachineConfigSpec')
        device_config_spec = []
        virtual_device_config = client_factory.create('ns0:VirtualDeviceConfigSpec')
        virtual_device_config.operation = "edit"
        device.connectable.connected=False
        virtual_device_config.device = device
        device_config_spec.append(virtual_device_config)
        config_spec.deviceChange = device_config_spec
        return config_spec
    return None

def detach_serial_port(session, instance):
    client_factory = session.vim.client.factory
    vm_ref = get_vm_ref(session, instance)
    serial_port_device = get_serial_port_device(session, vm_ref)

    reconfig_spec = get_disconnect_serial_port_spec(client_factory, serial_port_device)
    reconfigure_vm(session, vm_ref, reconfig_spec)
# Vsettan-only (prs-related) end


def get_vm_resize_spec(client_factory, vcpus, memory_mb, extra_specs,
                       metadata=None):
    """Provides updates for a VM spec."""
    resize_spec = client_factory.create('ns0:VirtualMachineConfigSpec')
    resize_spec.numCPUs = vcpus
    resize_spec.memoryMB = memory_mb
    resize_spec.cpuAllocation = _get_allocation_info(
        client_factory, extra_specs.cpu_limits,
        'ns0:ResourceAllocationInfo')
    if metadata:
        resize_spec.annotation = metadata
    return resize_spec


# Vsettan-only start hot resize
def get_disk_resize_spec(client_factory, device):
    resize_spec = client_factory.create('ns0:VirtualMachineConfigSpec')
    disk_spec = client_factory.create('ns0:VirtualDeviceConfigSpec')
    operation = client_factory.create('ns0:VirtualDeviceConfigSpecOperation')
    disk_spec.operation = operation.edit
    disk_spec.device = device
    resize_spec.deviceChange.append(disk_spec)
    return resize_spec
# Vsettan-only stop hot resize


def create_controller_spec(client_factory, key,
                           adapter_type=constants.DEFAULT_ADAPTER_TYPE):
    """Builds a Config Spec for the LSI or Bus Logic Controller's addition
    which acts as the controller for the virtual hard disk to be attached
    to the VM.
    """
    # Create a controller for the Virtual Hard Disk
    virtual_device_config = client_factory.create(
                            'ns0:VirtualDeviceConfigSpec')
    virtual_device_config.operation = "add"
    if adapter_type == constants.ADAPTER_TYPE_BUSLOGIC:
        virtual_controller = client_factory.create(
                                'ns0:VirtualBusLogicController')
    elif adapter_type == constants.ADAPTER_TYPE_LSILOGICSAS:
        virtual_controller = client_factory.create(
                                'ns0:VirtualLsiLogicSASController')
    elif adapter_type == constants.ADAPTER_TYPE_PARAVIRTUAL:
        virtual_controller = client_factory.create(
                                'ns0:ParaVirtualSCSIController')
    else:
        virtual_controller = client_factory.create(
                                'ns0:VirtualLsiLogicController')
    virtual_controller.key = key
    virtual_controller.busNumber = 0
    virtual_controller.sharedBus = "noSharing"
    virtual_device_config.device = virtual_controller
    return virtual_device_config


def convert_vif_model(name):
    """Converts standard VIF_MODEL types to the internal VMware ones."""
    if name == network_model.VIF_MODEL_E1000:
        return 'VirtualE1000'
    if name == network_model.VIF_MODEL_E1000E:
        return 'VirtualE1000e'
    if name == network_model.VIF_MODEL_PCNET:
        return 'VirtualPCNet32'
    if name == network_model.VIF_MODEL_SRIOV:
        return 'VirtualSriovEthernetCard'
    if name == network_model.VIF_MODEL_VMXNET:
        return 'VirtualVmxnet'
    if name == network_model.VIF_MODEL_VMXNET3:
        return 'VirtualVmxnet3'
    if name not in ALL_SUPPORTED_NETWORK_DEVICES:
        msg = _('%s is not supported.') % name
        raise exception.Invalid(msg)
    return name


def _create_vif_spec(client_factory, vif_info, vif_limits=None):
    """Builds a config spec for the addition of a new network
    adapter to the VM.
    """
    network_spec = client_factory.create('ns0:VirtualDeviceConfigSpec')
    network_spec.operation = "add"

    # Keep compatible with other Hyper vif model parameter.
    vif_info['vif_model'] = convert_vif_model(vif_info['vif_model'])

    vif = 'ns0:' + vif_info['vif_model']
    net_device = client_factory.create(vif)

    # NOTE(asomya): Only works on ESXi if the portgroup binding is set to
    # ephemeral. Invalid configuration if set to static and the NIC does
    # not come up on boot if set to dynamic.
    network_ref = vif_info['network_ref']
    network_name = vif_info['network_name']
    mac_address = vif_info['mac_address']
    backing = None
    if network_ref and network_ref['type'] == 'OpaqueNetwork':
        backing = client_factory.create(
                'ns0:VirtualEthernetCardOpaqueNetworkBackingInfo')
        backing.opaqueNetworkId = network_ref['network-id']
        backing.opaqueNetworkType = network_ref['network-type']
        # Configure externalId
        if network_ref['use-external-id']:
            # externalId is only supported from vCenter 6.0 onwards
            if hasattr(net_device, 'externalId'):
                net_device.externalId = vif_info['iface_id']
            else:
                dp = client_factory.create('ns0:DynamicProperty')
                dp.name = "__externalId__"
                dp.val = vif_info['iface_id']
                net_device.dynamicProperty = [dp]
    elif (network_ref and
            network_ref['type'] == "DistributedVirtualPortgroup"):
        backing = client_factory.create(
                'ns0:VirtualEthernetCardDistributedVirtualPortBackingInfo')
        portgroup = client_factory.create(
                    'ns0:DistributedVirtualSwitchPortConnection')
        portgroup.switchUuid = network_ref['dvsw']
        portgroup.portgroupKey = network_ref['dvpg']
        backing.port = portgroup
    else:
        backing = client_factory.create(
                  'ns0:VirtualEthernetCardNetworkBackingInfo')
        backing.deviceName = network_name

    connectable_spec = client_factory.create('ns0:VirtualDeviceConnectInfo')
    connectable_spec.startConnected = True
    connectable_spec.allowGuestControl = True
    connectable_spec.connected = True

    net_device.connectable = connectable_spec
    net_device.backing = backing

    # The Server assigns a Key to the device. Here we pass a -ve temporary key.
    # -ve because actual keys are +ve numbers and we don't
    # want a clash with the key that server might associate with the device
    net_device.key = -47
    net_device.addressType = "manual"
    net_device.macAddress = mac_address
    net_device.wakeOnLanEnabled = True

    # vnic limits are only supported from version 6.0
    if vif_limits and vif_limits.has_limits():
        if hasattr(net_device, 'resourceAllocation'):
            net_device.resourceAllocation = _get_allocation_info(
                client_factory, vif_limits,
                'ns0:VirtualEthernetCardResourceAllocation')
        else:
            msg = _('Limits only supported from vCenter 6.0 and above')
            raise exception.Invalid(msg)

    network_spec.device = net_device
    return network_spec


def get_network_attach_config_spec(client_factory, vif_info, index):
    """Builds the vif attach config spec."""
    config_spec = client_factory.create('ns0:VirtualMachineConfigSpec')
    vif_spec = _create_vif_spec(client_factory, vif_info)
    config_spec.deviceChange = [vif_spec]
    if vif_info['iface_id'] is not None:
        config_spec.extraConfig = [_iface_id_option_value(client_factory,
                                                          vif_info['iface_id'],
                                                          index)]
    return config_spec


def get_network_detach_config_spec(client_factory, device, port_index):
    """Builds the vif detach config spec."""
    config_spec = client_factory.create('ns0:VirtualMachineConfigSpec')
    virtual_device_config = client_factory.create(
                            'ns0:VirtualDeviceConfigSpec')
    virtual_device_config.operation = "remove"
    virtual_device_config.device = device
    config_spec.deviceChange = [virtual_device_config]
    # If a key is already present then it cannot be deleted, only updated.
    # This enables us to reuse this key if there is an additional
    # attachment. The keys need to be preserved. This is due to the fact
    # that there is logic on the ESX that does the network wiring
    # according to these values. If they are changed then this will
    # break networking to and from the interface.
    config_spec.extraConfig = [_iface_id_option_value(client_factory,
                                                      'free',
                                                      port_index)]
    return config_spec


def get_storage_profile_spec(session, storage_policy):
    """Gets the vm profile spec configured for storage policy."""
    profile_id = pbm.get_profile_id_by_name(session, storage_policy)
    if profile_id:
        client_factory = session.vim.client.factory
        storage_profile_spec = client_factory.create(
            'ns0:VirtualMachineDefinedProfileSpec')
        storage_profile_spec.profileId = profile_id.uniqueId
        return storage_profile_spec


def get_vmdk_attach_config_spec(client_factory,
                                disk_type=constants.DEFAULT_DISK_TYPE,
                                file_path=None,
                                disk_size=None,
                                linked_clone=False,
                                controller_key=None,
                                unit_number=None,
                                device_name=None,
                                disk_io_limits=None):
    """Builds the vmdk attach config spec."""
    config_spec = client_factory.create('ns0:VirtualMachineConfigSpec')

    device_config_spec = []
    virtual_device_config_spec = _create_virtual_disk_spec(client_factory,
                                controller_key, disk_type, file_path,
                                disk_size, linked_clone,
                                unit_number, device_name, disk_io_limits)

    device_config_spec.append(virtual_device_config_spec)

    config_spec.deviceChange = device_config_spec
    return config_spec


def get_cdrom_attach_config_spec(client_factory,
                                 datastore,
                                 file_path,
                                 controller_key,
                                 cdrom_unit_number):
    """Builds and returns the cdrom attach config spec."""
    config_spec = client_factory.create('ns0:VirtualMachineConfigSpec')

    device_config_spec = []
    virtual_device_config_spec = create_virtual_cdrom_spec(client_factory,
                                                           datastore,
                                                           controller_key,
                                                           file_path,
                                                           cdrom_unit_number)

    device_config_spec.append(virtual_device_config_spec)

    config_spec.deviceChange = device_config_spec
    return config_spec


def get_vmdk_detach_config_spec(client_factory, device,
                                destroy_disk=False):
    """Builds the vmdk detach config spec."""
    config_spec = client_factory.create('ns0:VirtualMachineConfigSpec')

    device_config_spec = []
    virtual_device_config_spec = detach_virtual_disk_spec(client_factory,
                                                          device,
                                                          destroy_disk)

    device_config_spec.append(virtual_device_config_spec)

    config_spec.deviceChange = device_config_spec
    return config_spec


def get_vm_extra_config_spec(client_factory, extra_opts):
    """Builds extra spec fields from a dictionary."""
    config_spec = client_factory.create('ns0:VirtualMachineConfigSpec')
    # add the key value pairs
    extra_config = []
    for key, value in six.iteritems(extra_opts):
        opt = client_factory.create('ns0:OptionValue')
        opt.key = key
        opt.value = value
        extra_config.append(opt)
        config_spec.extraConfig = extra_config
    return config_spec


def _get_device_capacity(device):
    # Devices pre-vSphere-5.5 only reports capacityInKB, which has
    # rounding inaccuracies. Use that only if the more accurate
    # attribute is absent.
    if hasattr(device, 'capacityInBytes'):
        return device.capacityInBytes
    else:
        return device.capacityInKB * units.Ki


def _get_device_disk_type(device):
    if getattr(device.backing, 'thinProvisioned', False):
        return constants.DISK_TYPE_THIN
    else:
        if getattr(device.backing, 'eagerlyScrub', False):
            return constants.DISK_TYPE_EAGER_ZEROED_THICK
        else:
            return constants.DEFAULT_DISK_TYPE


def get_vmdk_info(session, vm_ref, uuid=None):
    """Returns information for the primary VMDK attached to the given VM."""
    hardware_devices = session._call_method(vim_util,
            "get_dynamic_property", vm_ref, "VirtualMachine",
            "config.hardware.device")
    if hardware_devices.__class__.__name__ == "ArrayOfVirtualDevice":
        hardware_devices = hardware_devices.VirtualDevice
    vmdk_file_path = None
    vmdk_controller_key = None
    disk_type = None
    capacity_in_bytes = 0

    # Determine if we need to get the details of the root disk
    root_disk = None
    root_device = None
    if uuid:
        root_disk = '%s.vmdk' % uuid
    vmdk_device = None

    adapter_type_dict = {}
    for device in hardware_devices:
        if device.__class__.__name__ == "VirtualDisk":
            if device.backing.__class__.__name__ == \
                    "VirtualDiskFlatVer2BackingInfo":
                path = ds_obj.DatastorePath.parse(device.backing.fileName)
                if root_disk and path.basename == root_disk:
                    root_device = device
                elif device.deviceInfo.label == 'Hard disk 1':
                    root_device = device
                vmdk_device = device
        elif device.__class__.__name__ == "VirtualLsiLogicController":
            adapter_type_dict[device.key] = constants.DEFAULT_ADAPTER_TYPE
        elif device.__class__.__name__ == "VirtualBusLogicController":
            adapter_type_dict[device.key] = constants.ADAPTER_TYPE_BUSLOGIC
        elif device.__class__.__name__ == "VirtualIDEController":
            adapter_type_dict[device.key] = constants.ADAPTER_TYPE_IDE
        elif device.__class__.__name__ == "VirtualLsiLogicSASController":
            adapter_type_dict[device.key] = constants.ADAPTER_TYPE_LSILOGICSAS
        elif device.__class__.__name__ == "ParaVirtualSCSIController":
            adapter_type_dict[device.key] = constants.ADAPTER_TYPE_PARAVIRTUAL

    if root_disk:
        vmdk_device = root_device

    if vmdk_device:
        vmdk_file_path = vmdk_device.backing.fileName
        capacity_in_bytes = _get_device_capacity(vmdk_device)
        vmdk_controller_key = vmdk_device.controllerKey
        disk_type = _get_device_disk_type(vmdk_device)

    adapter_type = adapter_type_dict.get(vmdk_controller_key)
    return VmdkInfo(vmdk_file_path, adapter_type, disk_type,
                    capacity_in_bytes, vmdk_device)


scsi_controller_classes = {
    'ParaVirtualSCSIController': constants.ADAPTER_TYPE_PARAVIRTUAL,
    'VirtualLsiLogicController': constants.DEFAULT_ADAPTER_TYPE,
    'VirtualLsiLogicSASController': constants.ADAPTER_TYPE_LSILOGICSAS,
    'VirtualBusLogicController': constants.ADAPTER_TYPE_PARAVIRTUAL,
}


def get_scsi_adapter_type(hardware_devices):
    """Selects a proper iscsi adapter type from the existing
       hardware devices
    """
    if hardware_devices.__class__.__name__ == "ArrayOfVirtualDevice":
        hardware_devices = hardware_devices.VirtualDevice

    for device in hardware_devices:
        if device.__class__.__name__ in scsi_controller_classes:
            # find the controllers which still have available slots
            if len(device.device) < constants.SCSI_MAX_CONNECT_NUMBER:
                # return the first match one
                return scsi_controller_classes[device.__class__.__name__]
    raise exception.StorageError(
        reason=_("Unable to find iSCSI Target"))


def _find_controller_slot(controller_keys, taken, max_unit_number):
    for controller_key in controller_keys:
        for unit_number in range(max_unit_number):
            if unit_number not in taken.get(controller_key, []):
                return controller_key, unit_number


def _is_ide_controller(device):
    return device.__class__.__name__ == 'VirtualIDEController'


def _is_scsi_controller(device):
    return device.__class__.__name__ in ['VirtualLsiLogicController',
                                         'VirtualLsiLogicSASController',
                                         'VirtualBusLogicController',
                                         'ParaVirtualSCSIController']


def _find_allocated_slots(devices):
    """Return dictionary which maps controller_key to list of allocated unit
    numbers for that controller_key.
    """
    taken = {}
    for device in devices:
        if hasattr(device, 'controllerKey') and hasattr(device, 'unitNumber'):
            unit_numbers = taken.setdefault(device.controllerKey, [])
            unit_numbers.append(device.unitNumber)
        if _is_scsi_controller(device):
            # the SCSI controller sits on its own bus
            unit_numbers = taken.setdefault(device.key, [])
            unit_numbers.append(device.scsiCtlrUnitNumber)
    return taken


def allocate_controller_key_and_unit_number(client_factory, devices,
                                            adapter_type):
    """This function inspects the current set of hardware devices and returns
    controller_key and unit_number that can be used for attaching a new virtual
    disk to adapter with the given adapter_type.
    """
    if devices.__class__.__name__ == "ArrayOfVirtualDevice":
        devices = devices.VirtualDevice

    taken = _find_allocated_slots(devices)

    ret = None
    if adapter_type == constants.ADAPTER_TYPE_IDE:
        ide_keys = [dev.key for dev in devices if _is_ide_controller(dev)]
        ret = _find_controller_slot(ide_keys, taken, 2)
    elif adapter_type in [constants.DEFAULT_ADAPTER_TYPE,
                          constants.ADAPTER_TYPE_LSILOGICSAS,
                          constants.ADAPTER_TYPE_BUSLOGIC,
                          constants.ADAPTER_TYPE_PARAVIRTUAL]:
        scsi_keys = [dev.key for dev in devices if _is_scsi_controller(dev)]
        ret = _find_controller_slot(scsi_keys, taken, 16)
    if ret:
        return ret[0], ret[1], None

    # create new controller with the specified type and return its spec
    controller_key = -101
    controller_spec = create_controller_spec(client_factory, controller_key,
                                             adapter_type)
    return controller_key, 0, controller_spec


def get_rdm_disk(hardware_devices, uuid):
    """Gets the RDM disk key."""
    if hardware_devices.__class__.__name__ == "ArrayOfVirtualDevice":
        hardware_devices = hardware_devices.VirtualDevice

    for device in hardware_devices:
        if (device.__class__.__name__ == "VirtualDisk" and
            device.backing.__class__.__name__ ==
                "VirtualDiskRawDiskMappingVer1BackingInfo" and
                device.backing.lunUuid == uuid):
            return device


def get_vmdk_create_spec(client_factory, size_in_kb,
                         adapter_type=constants.DEFAULT_ADAPTER_TYPE,
                         disk_type=constants.DEFAULT_DISK_TYPE):
    """Builds the virtual disk create spec."""
    create_vmdk_spec = client_factory.create('ns0:FileBackedVirtualDiskSpec')
    create_vmdk_spec.adapterType = get_vmdk_adapter_type(adapter_type)
    create_vmdk_spec.diskType = disk_type
    create_vmdk_spec.capacityKb = size_in_kb
    return create_vmdk_spec


def create_virtual_cdrom_spec(client_factory,
                              datastore,
                              controller_key,
                              file_path,
                              cdrom_unit_number):
    """Builds spec for the creation of a new Virtual CDROM to the VM."""
    config_spec = client_factory.create(
        'ns0:VirtualDeviceConfigSpec')
    config_spec.operation = "add"

    cdrom = client_factory.create('ns0:VirtualCdrom')

    cdrom_device_backing = client_factory.create(
        'ns0:VirtualCdromIsoBackingInfo')
    cdrom_device_backing.datastore = datastore
    cdrom_device_backing.fileName = file_path

    cdrom.backing = cdrom_device_backing
    cdrom.controllerKey = controller_key
    cdrom.unitNumber = cdrom_unit_number
    cdrom.key = -1

    connectable_spec = client_factory.create('ns0:VirtualDeviceConnectInfo')
    connectable_spec.startConnected = True
    connectable_spec.allowGuestControl = False
    connectable_spec.connected = True

    cdrom.connectable = connectable_spec

    config_spec.device = cdrom
    return config_spec


def _create_virtual_disk_spec(client_factory, controller_key,
                              disk_type=constants.DEFAULT_DISK_TYPE,
                              file_path=None,
                              disk_size=None,
                              linked_clone=False,
                              unit_number=None,
                              device_name=None,
                              disk_io_limits=None):
    """Builds spec for the creation of a new/ attaching of an already existing
    Virtual Disk to the VM.
    """
    virtual_device_config = client_factory.create(
                            'ns0:VirtualDeviceConfigSpec')
    virtual_device_config.operation = "add"
    if (file_path is None) or linked_clone:
        virtual_device_config.fileOperation = "create"

    virtual_disk = client_factory.create('ns0:VirtualDisk')

    if disk_type == "rdm" or disk_type == "rdmp":
        disk_file_backing = client_factory.create(
                            'ns0:VirtualDiskRawDiskMappingVer1BackingInfo')
        disk_file_backing.compatibilityMode = "virtualMode" \
            if disk_type == "rdm" else "physicalMode"
        disk_file_backing.diskMode = "independent_persistent"
        disk_file_backing.deviceName = device_name or ""
    else:
        disk_file_backing = client_factory.create(
                            'ns0:VirtualDiskFlatVer2BackingInfo')
        disk_file_backing.diskMode = "persistent"
        if disk_type == constants.DISK_TYPE_THIN:
            disk_file_backing.thinProvisioned = True
        else:
            if disk_type == constants.DISK_TYPE_EAGER_ZEROED_THICK:
                disk_file_backing.eagerlyScrub = True
    disk_file_backing.fileName = file_path or ""

    connectable_spec = client_factory.create('ns0:VirtualDeviceConnectInfo')
    connectable_spec.startConnected = True
    connectable_spec.allowGuestControl = False
    connectable_spec.connected = True

    if not linked_clone:
        virtual_disk.backing = disk_file_backing
    else:
        virtual_disk.backing = copy.copy(disk_file_backing)
        virtual_disk.backing.fileName = ""
        virtual_disk.backing.parent = disk_file_backing
    virtual_disk.connectable = connectable_spec

    # The Server assigns a Key to the device. Here we pass a -ve random key.
    # -ve because actual keys are +ve numbers and we don't
    # want a clash with the key that server might associate with the device
    virtual_disk.key = -100
    virtual_disk.controllerKey = controller_key
    virtual_disk.unitNumber = unit_number or 0
    virtual_disk.capacityInKB = disk_size or 0

    if disk_io_limits and disk_io_limits.has_limits():
        virtual_disk.storageIOAllocation = _get_allocation_info(
            client_factory, disk_io_limits,
            'ns0:StorageIOAllocationInfo')

    virtual_device_config.device = virtual_disk

    return virtual_device_config


def detach_virtual_disk_spec(client_factory, device, destroy_disk=False):
    """Builds spec for the detach of an already existing Virtual Disk from VM.
    """
    virtual_device_config = client_factory.create(
                            'ns0:VirtualDeviceConfigSpec')
    virtual_device_config.operation = "remove"
    if destroy_disk:
        virtual_device_config.fileOperation = "destroy"
    virtual_device_config.device = device

    return virtual_device_config


def clone_vm_spec(client_factory, location,
                  power_on=False, snapshot=None, template=False, config=None):
    """Builds the VM clone spec."""
    clone_spec = client_factory.create('ns0:VirtualMachineCloneSpec')
    clone_spec.location = location
    clone_spec.powerOn = power_on
    if snapshot:
        clone_spec.snapshot = snapshot
    if config is not None:
        clone_spec.config = config
    clone_spec.template = template
    return clone_spec


def relocate_vm_spec(client_factory, datastore=None, host=None,
                     pool=None, # Vsettan-only (prs-related)
                     disk_move_type="moveAllDiskBackingsAndAllowSharing"):
    """Builds the VM relocation spec."""
    rel_spec = client_factory.create('ns0:VirtualMachineRelocateSpec')
    rel_spec.datastore = datastore
    rel_spec.diskMoveType = disk_move_type
    if host:
        rel_spec.host = host
    # Vsettan-only (prs-related) begin
    if pool:
        rel_spec.pool = pool
    # Vsettan-only (prs-related) end
    return rel_spec


def get_machine_id_change_spec(client_factory, machine_id_str):
    """Builds the machine id change config spec."""
    virtual_machine_config_spec = client_factory.create(
                                  'ns0:VirtualMachineConfigSpec')

    opt = client_factory.create('ns0:OptionValue')
    opt.key = "machine.id"
    opt.value = machine_id_str
    virtual_machine_config_spec.extraConfig = [opt]
    return virtual_machine_config_spec


def get_add_vswitch_port_group_spec(client_factory, vswitch_name,
                                    port_group_name, vlan_id):
    """Builds the virtual switch port group add spec."""
    vswitch_port_group_spec = client_factory.create('ns0:HostPortGroupSpec')
    vswitch_port_group_spec.name = port_group_name
    vswitch_port_group_spec.vswitchName = vswitch_name

    # VLAN ID of 0 means that VLAN tagging is not to be done for the network.
    vswitch_port_group_spec.vlanId = int(vlan_id)

    policy = client_factory.create('ns0:HostNetworkPolicy')
    nicteaming = client_factory.create('ns0:HostNicTeamingPolicy')
    nicteaming.notifySwitches = True
    policy.nicTeaming = nicteaming

    vswitch_port_group_spec.policy = policy
    return vswitch_port_group_spec


def get_vnc_config_spec(client_factory, port):
    """Builds the vnc config spec."""
    virtual_machine_config_spec = client_factory.create(
                                    'ns0:VirtualMachineConfigSpec')

    opt_enabled = client_factory.create('ns0:OptionValue')
    opt_enabled.key = "RemoteDisplay.vnc.enabled"
    opt_enabled.value = "true"
    opt_port = client_factory.create('ns0:OptionValue')
    opt_port.key = "RemoteDisplay.vnc.port"
    opt_port.value = port
    opt_keymap = client_factory.create('ns0:OptionValue')
    opt_keymap.key = "RemoteDisplay.vnc.keyMap"
    opt_keymap.value = CONF.vnc.keymap

    extras = [opt_enabled, opt_port, opt_keymap]

    virtual_machine_config_spec.extraConfig = extras
    return virtual_machine_config_spec


def get_vnc_port(session):
    """Return VNC port for an VM or None if there is no available port."""
    min_port = CONF.vmware.vnc_port
    port_total = CONF.vmware.vnc_port_total
    allocated_ports = _get_allocated_vnc_ports(session)
    max_port = min_port + port_total
    for port in range(min_port, max_port):
        if port not in allocated_ports:
            return port
    raise exception.ConsolePortRangeExhausted(min_port=min_port,
                                              max_port=max_port)


def _get_allocated_vnc_ports(session):
    """Return an integer set of all allocated VNC ports."""
    # TODO(rgerganov): bug #1256944
    # The VNC port should be unique per host, not per vCenter
    vnc_ports = set()
    result = session._call_method(vim_util, "get_objects",
                                  "VirtualMachine", [VNC_CONFIG_KEY])
    while result:
        for obj in result.objects:
            if not hasattr(obj, 'propSet'):
                continue
            dynamic_prop = obj.propSet[0]
            option_value = dynamic_prop.val
            vnc_port = option_value.value
            vnc_ports.add(int(vnc_port))
        result = session._call_method(vutil, 'continue_retrieval',
                                      result)
    return vnc_ports


# NOTE(mdbooth): this convenience function is temporarily duplicated in
# ds_util. The correct fix is to handle paginated results as they are returned
# from the relevant vim_util function. However, vim_util is currently
# effectively deprecated as we migrate to oslo.vmware. This duplication will be
# removed when we fix it properly in oslo.vmware.
def _get_token(results):
    """Get the token from the property results."""
    return getattr(results, 'token', None)


def _get_reference_for_value(results, value):
    for object in results.objects:
        if object.obj.value == value:
            return object


def _get_object_for_value(results, value):
    for object in results.objects:
        if hasattr(object, "propSet") and object.propSet:
            if object.propSet[0].val == value:
                return object.obj


def _get_object_for_optionvalue(results, value):
    for object in results.objects:
        if hasattr(object, "propSet") and object.propSet:
            if object.propSet[0].val.value == value:
                return object.obj


def _get_object_from_results(session, results, value, func):
    while results:
        object = func(results, value)
        if object:
            session._call_method(vutil, 'cancel_retrieval',
                                 results)
            return object
        results = session._call_method(vutil, 'continue_retrieval',
                                       results)


def _cancel_retrieve_if_necessary(session, results):
    token = _get_token(results)
    if token:
        results = session._call_method(vim_util,
                                       "cancel_retrieve",
                                       token)


def _get_vm_ref_from_name(session, vm_name):
    """Get reference to the VM with the name specified."""
    vms = session._call_method(vim_util, "get_objects",
                "VirtualMachine", ["name"])
    return _get_object_from_results(session, vms, vm_name,
                                    _get_object_for_value)


# Vsettan-only start
def get_template_ref_from_uuid(session, instanceuuid):
    """Get reference to the Template with the instanceuuid specified."""
    vms = session._call_method(vim_util, "get_objects",
                "VirtualMachine", ["config.instanceUuid"])
    return _get_object_from_results(session, vms, instanceuuid,
                                    _get_object_for_value)
#Vsettan-only end


@vm_ref_cache_from_name
def get_vm_ref_from_name(session, vm_name):
    return (_get_vm_ref_from_vm_uuid(session, vm_name) or
            _get_vm_ref_from_name(session, vm_name))


def _get_vm_ref_from_uuid(session, instance_uuid):
    """Get reference to the VM with the uuid specified.

    This method reads all of the names of the VM's that are running
    on the backend, then it filters locally the matching
    instance_uuid. It is far more optimal to use
    _get_vm_ref_from_vm_uuid.
    """
    vms = session._call_method(vim_util, "get_objects",
                "VirtualMachine", ["name"])
    return _get_object_from_results(session, vms, instance_uuid,
                                    _get_object_for_value)


def _get_vm_ref_from_vm_uuid(session, instance_uuid):
    """Get reference to the VM.

    The method will make use of FindAllByUuid to get the VM reference.
    This method finds all VM's on the backend that match the
    instance_uuid, more specifically all VM's on the backend that have
    'config_spec.instanceUuid' set to 'instance_uuid'.
    """
    vm_refs = session._call_method(
        session.vim,
        "FindAllByUuid",
        session.vim.service_content.searchIndex,
        uuid=instance_uuid,
        vmSearch=True,
        instanceUuid=True)
    if vm_refs:
        return vm_refs[0]


def _get_vm_ref_from_extraconfig(session, instance_uuid):
    """Get reference to the VM with the uuid specified."""
    vms = session._call_method(vim_util, "get_objects",
                "VirtualMachine", ['config.extraConfig["nvp.vm-uuid"]'])
    return _get_object_from_results(session, vms, instance_uuid,
                                     _get_object_for_optionvalue)


@vm_ref_cache_from_instance
def get_vm_ref(session, instance):
    """Get reference to the VM through uuid or vm name."""
    uuid = instance['uuid'] #Vsettan-only (discovery need)
    vm_ref = (search_vm_ref_by_identifier(session, uuid) or
            _get_vm_ref_from_name(session, instance.display_name) or # Vsettan-only
            _get_vm_ref_from_name(session, get_vm_name_for_vcenter(instance)) or # Vsettan-only
            _get_vm_ref_from_name(session, instance.name))
    if vm_ref is None:
        raise exception.InstanceNotFound(instance_id=uuid)
    return vm_ref


def search_vm_ref_by_identifier(session, identifier):
    """Searches VM reference using the identifier.

    This method is primarily meant to separate out part of the logic for
    vm_ref search that could be use directly in the special case of
    migrating the instance. For querying VM linked to an instance always
    use get_vm_ref instead.
    """
    vm_ref = (_get_vm_ref_from_vm_uuid(session, identifier) or
              _get_vm_ref_from_extraconfig(session, identifier) or
              _get_vm_ref_from_uuid(session, identifier))
    return vm_ref


def get_host_ref_for_vm(session, instance):
    """Get a MoRef to the ESXi host currently running an instance."""

    vm_ref = get_vm_ref(session, instance)
    return session._call_method(vim_util, "get_dynamic_property",
                                vm_ref, "VirtualMachine", "runtime.host")


def get_host_name_for_vm(session, instance):
    """Get the hostname of the ESXi host currently running an instance."""

    host_ref = get_host_ref_for_vm(session, instance)
    return session._call_method(vim_util, "get_dynamic_property",
                                host_ref, "HostSystem", "name")


def get_vm_state(session, instance):
    vm_ref = get_vm_ref(session, instance)
    vm_state = session._call_method(vim_util, "get_dynamic_property",
                vm_ref, "VirtualMachine", "runtime.powerState")
    return vm_state


def get_stats_from_cluster(session, cluster=None, resource_pool=None): #Vsettan-only
    """Get the aggregate resource stats of a cluster."""
    vcpus = 0
    mem_info = {'total': 0, 'free': 0}
    #Vsettan-only begin
    if resource_pool:
        memory_usage = session._call_method(vim_util, "get_dynamic_property",
                            resource_pool, "ResourcePool",
                            "summary.runtime.memory")
        if memory_usage:
            # maxUsage is the memory limit of the cluster available to VM's
            mem_info['total'] = int(memory_usage.maxUsage / units.Mi)
            # overallUsage is the hypervisor's view of memory usage by VM's
            consumed = int(memory_usage.overallUsage / units.Mi)
            mem_info['free'] = mem_info['total'] - consumed
        stats = {'vcpus': vcpus, 'mem': mem_info}
        return stats
    #Vsettan-only end
    # Get the Host and Resource Pool Managed Object Refs
    prop_dict = session._call_method(vim_util, "get_dynamic_properties",
                                     cluster, "ClusterComputeResource",
                                     ["host", "resourcePool"])
    if prop_dict:
        host_ret = prop_dict.get('host')
        if host_ret:
            host_mors = host_ret.ManagedObjectReference
            result = session._call_method(vim_util,
                         "get_properties_for_a_collection_of_objects",
                         "HostSystem", host_mors,
                         ["summary.hardware", "summary.runtime"])
            for obj in result.objects:
                hardware_summary = obj.propSet[0].val
                runtime_summary = obj.propSet[1].val
                if (runtime_summary.inMaintenanceMode is False and
                    runtime_summary.connectionState == "connected"):
                    # Total vcpus is the sum of all pCPUs of individual hosts
                    # The overcommitment ratio is factored in by the scheduler
                    vcpus += hardware_summary.numCpuThreads

        res_mor = prop_dict.get('resourcePool')
        if res_mor:
            res_usage = session._call_method(vim_util, "get_dynamic_property",
                            res_mor, "ResourcePool", "summary.runtime.memory")
            if res_usage:
                # maxUsage is the memory limit of the cluster available to VM's
                mem_info['total'] = int(res_usage.maxUsage / units.Mi)
                # overallUsage is the hypervisor's view of memory usage by VM's
                consumed = int(res_usage.overallUsage / units.Mi)
                mem_info['free'] = mem_info['total'] - consumed
    stats = {'vcpus': vcpus, 'mem': mem_info}
    return stats

# Vsettan-only (prs-related) start
def get_stats_from_host(session, host_mor=None):
    stats = { 'vcpus': 0, 'cpu_info': {}, 'host_memory_total': 0,
             'host_memory_free':0, 'hypervisor_type': 'VMware ESXi',
             'hypervisor_version':0 }
    summary = session._call_method(vim_util, "get_dynamic_property",
                                            host_mor, "HostSystem", "summary")
    if summary and summary.quickStats != '':
        stats["vcpus"] = summary.hardware.numCpuThreads
        stats["cpu_info"] = \
            {"vendor": summary.hardware.vendor,
             "model": summary.hardware.cpuModel,
             "topology": {"cores": summary.hardware.numCpuCores,
                          "sockets": summary.hardware.numCpuPkgs,
                          "threads": summary.hardware.numCpuThreads}
            }
        stats["host_memory_total"] = summary.hardware.memorySize / units.Mi
        stats["host_memory_free"] = stats["host_memory_total"] - \
                                summary.quickStats.overallMemoryUsage
        stats["hypervisor_type"] = summary.config.product.name
        stats["hypervisor_version"] = utils.convert_version_to_int(
                str(summary.config.product.version))
    return stats

def is_root_resource_pool(session, resource_Pool=None):
    """Determine is root resource pool or not"""
    if resource_Pool is not None:
        # For root resource pool, the flag is its owner 
        # and parent are same compute resource.
        parent_res =  session._call_method(vim_util,
                                       'get_dynamic_property',
                                       resource_Pool, 'ResourcePool',
                                       'parent')
        owner_res = session._call_method(vim_util,
                                       'get_dynamic_property',
                                       resource_Pool, 'ResourcePool',
                                       'owner')
        if (parent_res._type == 'ComputeResource' and
             owner_res._type == 'ComputeResource' and
             parent_res.value == owner_res.value):
            return True
    return False

def get_host_summary(session, host_mor):
    return session._call_method(vim_util, "get_dynamic_property",
                                host_mor, "HostSystem", "summary")
# Vsettan-only (prs-related) end

def get_host_ref(session, cluster=None):
    """Get reference to a host within the cluster specified."""
    if cluster is None:
        results = session._call_method(vim_util, "get_objects",
                                       "HostSystem")
        session._call_method(vutil, 'cancel_retrieval',
                             results)
        host_mor = results.objects[0].obj
    else:
        host_ret = session._call_method(vim_util, "get_dynamic_property",
                                        cluster, "ClusterComputeResource",
                                        "host")
        if not host_ret or not host_ret.ManagedObjectReference:
            msg = _('No host available on cluster')
            raise exception.NoValidHost(reason=msg)
        host_mor = host_ret.ManagedObjectReference[0]

    return host_mor


def propset_dict(propset):
    """Turn a propset list into a dictionary

    PropSet is an optional attribute on ObjectContent objects
    that are returned by the VMware API.

    You can read more about these at:
    | http://pubs.vmware.com/vsphere-51/index.jsp
    |    #com.vmware.wssdk.apiref.doc/
    |        vmodl.query.PropertyCollector.ObjectContent.html

    :param propset: a property "set" from ObjectContent
    :return: dictionary representing property set
    """
    if propset is None:
        return {}

    return {prop.name: prop.val for prop in propset}


def get_vmdk_backed_disk_uuid(hardware_devices, volume_uuid):
    if hardware_devices.__class__.__name__ == "ArrayOfVirtualDevice":
        hardware_devices = hardware_devices.VirtualDevice

    for device in hardware_devices:
        if (device.__class__.__name__ == "VirtualDisk" and
                device.backing.__class__.__name__ ==
                "VirtualDiskFlatVer2BackingInfo" and
                volume_uuid in device.backing.fileName):
            return device.backing.uuid


def get_vmdk_backed_disk_device(hardware_devices, uuid):
    if hardware_devices.__class__.__name__ == "ArrayOfVirtualDevice":
        hardware_devices = hardware_devices.VirtualDevice

    for device in hardware_devices:
        if (device.__class__.__name__ == "VirtualDisk" and
                device.backing.__class__.__name__ ==
                "VirtualDiskFlatVer2BackingInfo" and
                device.backing.uuid == uuid):
            return device


def get_vmdk_volume_disk(hardware_devices, path=None):
    if hardware_devices.__class__.__name__ == "ArrayOfVirtualDevice":
        hardware_devices = hardware_devices.VirtualDevice

    for device in hardware_devices:
        if (device.__class__.__name__ == "VirtualDisk"):
            if not path or path == device.backing.fileName:
                return device

 # Vsettan-only start
def get_res_pool_ref(session, cluster,
                     host=None,
                     res_pool_name=None):
    """Get the resource pool."""
    # Get the root resource pool of the cluster
    if cluster is None:
        if res_pool_name and host:
            return get_pool_refs_by_host(session, host, res_pool_name)
        else:
            # With no cluster named, use the root resource pool.
            results = session._call_method(vim_util, "get_objects",
                                       "ResourcePool")
            _cancel_retrieve_if_necessary(session, results)
            # The 0th resource pool is always the root resource pool on both ESX
            # and vCenter.
            res_pool_ref = results.objects[0].obj
    else:
        if res_pool_name:
            # If the object type is resource pool, which can either be within
            # esxi host system or within a cluster, resturn the pool.
            obj_contents = session._call_method(vim_util,
                                                "get_contained_objects",
                                                cluster, "ResourcePool")
            res_pool_ref = _get_object_from_results(session, obj_contents,
                                                    res_pool_name,
                                                    _get_object_for_value)
        else:
            # Get the root resource pool of the cluster
            res_pool_ref = session._call_method(vim_util,
                                                "get_dynamic_property",
                                                cluster,
                                                "ClusterComputeResource",
                                                "resourcePool")
    return res_pool_ref
 # Vsettan-only end

def get_all_cluster_mors(session):
    """Get all the clusters in the vCenter."""
    try:
        results = session._call_method(vim_util, "get_objects",
                                        "ClusterComputeResource", ["name"])
        session._call_method(vutil, 'cancel_retrieval',
                             results)
        return results.objects

    except Exception as excep:
        LOG.warning(_LW("Failed to get cluster references %s"), excep)


def get_cluster_ref_by_name(session, cluster_name):
    """Get reference to the vCenter cluster with the specified name."""
    all_clusters = get_all_cluster_mors(session)
    for cluster in all_clusters:
        if (hasattr(cluster, 'propSet') and
                    cluster.propSet[0].val == cluster_name):
            return cluster.obj


def get_all_res_pool_mors(session):
    """Get all the resource pools in the vCenter."""
    try:
        results = session._call_method(vim_util, "get_objects",
                                             "ResourcePool")

        _cancel_retrieve_if_necessary(session, results)
        return results.objects
    except Exception as excep:
        LOG.warning(_LW("Failed to get resource pool references " "%s"), excep)


def get_dynamic_property_mor(session, mor_ref, attribute):
    """Get the value of an attribute for a given managed object."""
    return session._call_method(vim_util, "get_dynamic_property",
                                mor_ref, mor_ref._type, attribute)


def find_entity_mor(entity_list, entity_name):
    """Returns managed object ref for given cluster or resource pool name."""
    return [mor for mor in entity_list if (hasattr(mor, 'propSet') and
                                           mor.propSet[0].val == entity_name)]


# Vsettan-only start
def get_pool_refs_by_cluster(session, cluster_name, resource_pool):
    clusters = session._call_method(vim_util, "get_objects",
                                    "ClusterComputeResource", ["name"])
    _cancel_retrieve_if_necessary(session, clusters)
    cluster_mor = _get_object_for_value(clusters, cluster_name)
    obj_contents = session._call_method(vim_util,
                                        "get_contained_objects",
                                        cluster_mor, "ResourcePool")
    res_pool_ref = _get_object_from_results(session, obj_contents,
                                            resource_pool,
                                            _get_object_for_value)
    return res_pool_ref, cluster_mor

def get_pool_refs_by_host(session, host, resource_pool=None):
    host_objs = session._call_method(vim_util, "get_objects",
                                    "HostSystem", ["name"])
    _cancel_retrieve_if_necessary(session, host_objs)
    host_mor = _get_object_for_value(host_objs, host)

    if not host_mor:
        raise exception.NotFound(_("The host '%s' can not be found,"
                                   "aborting getting resource pool"
                                   "by host '%s'.")
                                 % (host, host))

    compute_res = session._call_method(vim_util,
                                       'get_dynamic_property',
                                       host_mor, 'HostSystem',
                                       'parent')
    obj_contents = session._call_method(vim_util,
                                        "get_contained_objects",
                                        compute_res, "ResourcePool")
    # Vsettan-only (prs-related) start
    # If host managed by VMware cluster, there is no host resource pool.
    # so raise exception here
    if compute_res._type == "ClusterComputeResource":
        raise exception.NotFound(_("Host %s managed by cluster and have not "
                                   "root resource pool") % host)
    # If not specified resource pool, use ESX host's root resource pool instead
    if resource_pool is None:
        res_pool_ref = obj_contents.objects[0].obj
    # Vsettan-only (prs-related) end
    else:
        res_pool_ref = _get_object_from_results(session, obj_contents,
                                                resource_pool,
                                                 _get_object_for_value)

    return res_pool_ref, host_mor
# Vsettan-only end


def get_all_cluster_refs_by_name(session, path_list):
    """Get reference to the Cluster, ResourcePool with the path specified.

    The path is the display name. This can be the full path as well.
    The input will have the list of clusters and resource pool names
    """
    cls = get_all_cluster_mors(session)
    if not cls:
        return {}
    res = get_all_res_pool_mors(session)
    if not res:
        return {}
    path_list = [path.strip() for path in path_list]
    list_obj = []
    for entity_path in path_list:
        # entity_path could be unique cluster and/or resource-pool name
        res_mor = find_entity_mor(res, entity_path)
        cls_mor = find_entity_mor(cls, entity_path)
        cls_mor.extend(res_mor)
        for mor in cls_mor:
            list_obj.append((mor.obj, mor.propSet[0].val))
    return get_dict_mor(session, list_obj)


def get_dict_mor(session, list_obj):
    """The input is a list of objects in the form
    (manage_object,display_name)
    The managed object will be in the form
    { value = "domain-1002", _type = "ClusterComputeResource" }

    Output data format:
    | dict_mors = {
    |              'respool-1001': { 'cluster_mor': clusterMor,
    |                                'res_pool_mor': resourcePoolMor,
    |                                'name': display_name },
    |              'domain-1002': { 'cluster_mor': clusterMor,
    |                                'res_pool_mor': resourcePoolMor,
    |                                'name': display_name },
    |            }

    """
    dict_mors = {}
    for obj_ref, path in list_obj:
        if obj_ref._type == "ResourcePool":
            # Get owner cluster-ref mor
            cluster_ref = get_dynamic_property_mor(session, obj_ref, "owner")
            dict_mors[obj_ref.value] = {'cluster_mor': cluster_ref,
                                        'res_pool_mor': obj_ref,
                                        'name': path,
                                        }
        else:
            # Get default resource pool of the cluster
            res_pool_ref = get_dynamic_property_mor(session,
                                                    obj_ref, "resourcePool")
            dict_mors[obj_ref.value] = {'cluster_mor': obj_ref,
                                        'res_pool_mor': res_pool_ref,
                                        'name': path,
                                        }
    return dict_mors


def get_vmdk_adapter_type(adapter_type):
    """Return the adapter type to be used in vmdk descriptor.

    Adapter type in vmdk descriptor is same for LSI-SAS, LSILogic & ParaVirtual
    because Virtual Disk Manager API does not recognize the newer controller
    types.
    """
    if adapter_type in [constants.ADAPTER_TYPE_LSILOGICSAS,
                        constants.ADAPTER_TYPE_PARAVIRTUAL]:
        vmdk_adapter_type = constants.DEFAULT_ADAPTER_TYPE
    else:
        vmdk_adapter_type = adapter_type
    return vmdk_adapter_type


def create_vm(session, instance, vm_folder, config_spec, res_pool_ref):
    """Create VM on ESX host."""
    LOG.debug("Creating VM on the ESX host", instance=instance)
    vm_create_task = session._call_method(
        session.vim,
        "CreateVM_Task", vm_folder,
        config=config_spec, pool=res_pool_ref)
    try:
        task_info = session._wait_for_task(vm_create_task)
    except vexc.VMwareDriverException:
        # An invalid guestId will result in an error with no specific fault
        # type and the generic error 'A specified parameter was not correct'.
        # As guestId is user-editable, we try to help the user out with some
        # additional information if we notice that guestId isn't in our list of
        # known-good values.
        # We don't check this in advance or do anything more than warn because
        # we can't guarantee that our list of known-good guestIds is complete.
        # Consequently, a value which we don't recognise may in fact be valid.
        with excutils.save_and_reraise_exception():
            if config_spec.guestId not in constants.VALID_OS_TYPES:
                LOG.warning(_LW('vmware_ostype from image is not recognised: '
                                '\'%(ostype)s\'. An invalid os type may be '
                                'one cause of this instance creation failure'),
                         {'ostype': config_spec.guestId})
    LOG.debug("Created VM on the ESX host", instance=instance)
    return task_info.result


def destroy_vm(session, instance, vm_ref=None):
    """Destroy a VM instance. Assumes VM is powered off."""
    try:
        if not vm_ref:
            vm_ref = get_vm_ref(session, instance)
        LOG.debug("Destroying the VM", instance=instance)
        destroy_task = session._call_method(session.vim, "Destroy_Task",
                                            vm_ref)
        session._wait_for_task(destroy_task)
        LOG.info(_LI("Destroyed the VM"), instance=instance)
    except Exception:
        LOG.exception(_LE('Destroy VM failed'), instance=instance)


def create_virtual_disk(session, dc_ref, adapter_type, disk_type,
                        virtual_disk_path, size_in_kb):
    # Create a Virtual Disk of the size of the flat vmdk file. This is
    # done just to generate the meta-data file whose specifics
    # depend on the size of the disk, thin/thick provisioning and the
    # storage adapter type.
    LOG.debug("Creating Virtual Disk of size  "
              "%(vmdk_file_size_in_kb)s KB and adapter type "
              "%(adapter_type)s on the data store",
              {"vmdk_file_size_in_kb": size_in_kb,
               "adapter_type": adapter_type})

    vmdk_create_spec = get_vmdk_create_spec(
            session.vim.client.factory,
            size_in_kb,
            adapter_type,
            disk_type)

    vmdk_create_task = session._call_method(
            session.vim,
            "CreateVirtualDisk_Task",
            session.vim.service_content.virtualDiskManager,
            name=virtual_disk_path,
            datacenter=dc_ref,
            spec=vmdk_create_spec)

    session._wait_for_task(vmdk_create_task)
    LOG.debug("Created Virtual Disk of size %(vmdk_file_size_in_kb)s"
              " KB and type %(disk_type)s",
              {"vmdk_file_size_in_kb": size_in_kb,
               "disk_type": disk_type})


def copy_virtual_disk(session, dc_ref, source, dest):
    """Copy a sparse virtual disk to a thin virtual disk.

    This is also done to generate the meta-data file whose specifics
    depend on the size of the disk, thin/thick provisioning and the
    storage adapter type.

    :param session: - session for connection
    :param dc_ref: - data center reference object
    :param source: - source datastore path
    :param dest: - destination datastore path
    :returns: None
    """
    LOG.debug("Copying Virtual Disk %(source)s to %(dest)s",
              {'source': source, 'dest': dest})
    vim = session.vim
    vmdk_copy_task = session._call_method(
            vim,
            "CopyVirtualDisk_Task",
            vim.service_content.virtualDiskManager,
            sourceName=source,
            sourceDatacenter=dc_ref,
            destName=dest)
    session._wait_for_task(vmdk_copy_task)
    LOG.debug("Copied Virtual Disk %(source)s to %(dest)s",
              {'source': source, 'dest': dest})


def reconfigure_vm(session, vm_ref, config_spec):
    """Reconfigure a VM according to the config spec."""
    reconfig_task = session._call_method(session.vim,
                                         "ReconfigVM_Task", vm_ref,
                                         spec=config_spec)
    session._wait_for_task(reconfig_task)


# Vsettan-ONLY START snapshot to template
def clone_vmref_to_template(session, template_name, vm_ref, host_ref, ds_ref,
                            vmfolder_ref):
    """Clone VM to template
    """
    if vm_ref is None:
        LOG.warn(_("vmwareapi:vm_util:clone_vmref_to_template, called "
                   "with vm_ref=None"))
        raise vexc.MissingParameter(param="vm_ref")
    # Get the clone vm spec
    client_factory = session.vim.client.factory
    rel_spec = relocate_vm_spec(client_factory)
    clone_spec = clone_vm_spec(client_factory, rel_spec, template=True)
    # Clone VM to templte
    vm_clone_task = session._call_method(session.vim, "CloneVM_Task",
                                         vm_ref, folder=vmfolder_ref,
                                         name=template_name, spec=clone_spec)
    session._wait_for_task(vm_clone_task)
    LOG.debug("Cloning VM to template %s complete", template_name)
# Vsettan-ONLY STOP snapshot to template


def clone_vmref_for_instance(session, instance, vm_ref, host_ref, ds_ref,
                                vmfolder_ref,
                                rp_ref=None): # Vsettan-only (prs-related)
    """Clone VM and link the cloned VM to the instance.

    Clones the passed vm_ref into a new VM and links the cloned vm to
    the passed instance.
    """
    instance_name = get_vm_name_for_vcenter(instance) #Vsettan-only
    if vm_ref is None:
        LOG.warning(_LW("vmwareapi:vm_util:clone_vmref_for_instance, called "
                        "with vm_ref=None"))
        raise vexc.MissingParameter(param="vm_ref")
    # Get the clone vm spec
    client_factory = session.vim.client.factory
    rel_spec = relocate_vm_spec(client_factory, ds_ref, host_ref,
                    rp_ref, # Vsettan-only (prs-related)
                    disk_move_type='moveAllDiskBackingsAndDisallowSharing')
    extra_opts = {'nvp.vm-uuid': instance['uuid']}
    config_spec = get_vm_extra_config_spec(client_factory, extra_opts)
    config_spec.instanceUuid = instance['uuid']
    clone_spec = clone_vm_spec(client_factory, rel_spec, config=config_spec)

    # Clone VM on ESX host
    LOG.debug("Cloning VM for instance %s", instance['uuid'],
              instance=instance)
    vm_clone_task = session._call_method(session.vim, "CloneVM_Task",
                                         vm_ref, folder=vmfolder_ref,
                                         name=instance_name, #Vsettan-only
                                         spec=clone_spec)
    session._wait_for_task(vm_clone_task)
    LOG.debug("Cloned VM for instance %s", instance['uuid'],
              instance=instance)
    # Invalidate the cache, so that it is refetched the next time
    # Vsettan-only start
    # When CONF.vmware.use_displayname_uuid_for_vmname = true, 2 caches
    # are stored, delete both.
    vm_ref_cache_delete(instance_name)
    # Vsettan-only end
    vm_ref_cache_delete(instance['uuid'])


def disassociate_vmref_from_instance(session, instance, vm_ref=None,
                                      suffix='-orig'):
    """Disassociates the VM linked to the instance.

    Disassociates the VM linked to the instance by performing the following
    1. Update the extraConfig property for nvp.vm-uuid to be replaced with
    instance[uuid]+suffix
    2. Rename the VM to be instance[uuid]+suffix or
    display_name-instance[uuid]+suffix instead #Vsettan-only
    3. Reset the instanceUUID of the VM to a new generated value
    """
    instance_name = get_vm_name_for_vcenter(instance) #Vsettan-only
    if vm_ref is None:
        vm_ref = get_vm_ref(session, instance)
    extra_opts = {'nvp.vm-uuid': instance['uuid'] + suffix}
    client_factory = session.vim.client.factory
    reconfig_spec = get_vm_extra_config_spec(client_factory, extra_opts)
    reconfig_spec.name = instance_name + suffix #Vsettan-only
    reconfig_spec.instanceUuid = ''
    LOG.debug("Disassociating VM from instance %s", instance['uuid'],
              instance=instance)
    reconfigure_vm(session, vm_ref, reconfig_spec)
    LOG.debug("Disassociated VM from instance %s", instance['uuid'],
              instance=instance)
    # Invalidate the cache, so that it is refetched the next time
    # Vsettan-only start
    # When CONF.vmware.use_displayname_uuid_for_vmname = true, 2 caches
    # are stored, delete both.
    vm_ref_cache_delete(instance_name)
    # Vsettan-only end
    vm_ref_cache_delete(instance['uuid'])


def associate_vmref_for_instance(session, instance, vm_ref=None,
                                    suffix='-orig'):
    """Associates the VM to the instance.

    Associates the VM to the instance by performing the following
    1. Update the extraConfig property for nvp.vm-uuid to be replaced with
    instance[uuid]
    2. Rename the VM to be either instance[uuid] or display_name-instance[uuid] #Vsettan-only
    3. Reset the instanceUUID of the VM to be instance[uuid]
    """
    instance_name = get_vm_name_for_vcenter(instance) #Vsettan-only
    if vm_ref is None:
        vm_ref = search_vm_ref_by_identifier(session,
                                             instance_name + suffix) #Vsettan-only
        if vm_ref is None:
            raise exception.InstanceNotFound(instance_id=instance_name
                                            + suffix) #Vsettan-only
    extra_opts = {'nvp.vm-uuid': instance['uuid']}
    client_factory = session.vim.client.factory
    reconfig_spec = get_vm_extra_config_spec(client_factory, extra_opts)
    reconfig_spec.name = instance_name #Vsettan-only
    reconfig_spec.instanceUuid = instance['uuid']
    LOG.debug("Associating VM to instance %s", instance['uuid'],
              instance=instance)
    reconfigure_vm(session, vm_ref, reconfig_spec)
    LOG.debug("Associated VM to instance %s", instance['uuid'],
              instance=instance)
    # Invalidate the cache, so that it is refetched the next time
    # Vsettan-only start
    # When CONF.vmware.use_displayname_uuid_for_vmname = true, 2 caches
    # are stored, delete both.
    vm_ref_cache_delete(instance_name)
    # Vsettan-only end
    vm_ref_cache_delete(instance['uuid'])


def power_on_instance(session, instance, vm_ref=None):
    """Power on the specified instance."""

    if vm_ref is None:
        vm_ref = get_vm_ref(session, instance)

    LOG.debug("Powering on the VM", instance=instance)
    try:
        poweron_task = session._call_method(
                                    session.vim,
                                    "PowerOnVM_Task", vm_ref)
        session._wait_for_task(poweron_task)
        LOG.debug("Powered on the VM", instance=instance)
    except vexc.InvalidPowerStateException:
        LOG.debug("VM already powered on", instance=instance)


def get_values_from_object_properties(session, props):
    """Get the specific values from a object list.

    The object values will be returned as a dictionary.
    """
    dictionary = {}
    while props:
        for elem in props.objects:
            propdict = propset_dict(elem.propSet)
            dictionary.update(propdict)
        token = _get_token(props)
        if not token:
            break

        props = session._call_method(vim_util,
                                     "continue_to_get_objects",
                                     token)
    return dictionary


def _get_vm_port_indices(session, vm_ref):
    extra_config = session._call_method(vim_util,
                                        'get_dynamic_property',
                                        vm_ref, 'VirtualMachine',
                                        'config.extraConfig')
    ports = []
    if extra_config is not None:
        options = extra_config.OptionValue
        for option in options:
            if (option.key.startswith('nvp.iface-id.') and
                    option.value != 'free'):
                ports.append(int(option.key.split('.')[2]))
    return ports


def get_attach_port_index(session, vm_ref):
    """Get the first free port index."""
    ports = _get_vm_port_indices(session, vm_ref)
    # No ports are configured on the VM
    if not ports:
        return 0
    ports.sort()
    configured_ports_len = len(ports)
    # Find the first free port index
    for port_index in range(configured_ports_len):
        if port_index != ports[port_index]:
            return port_index
    return configured_ports_len


def get_vm_detach_port_index(session, vm_ref, iface_id):
    extra_config = session._call_method(vim_util,
                                        'get_dynamic_property',
                                        vm_ref, 'VirtualMachine',
                                        'config.extraConfig')
    if extra_config is not None:
        options = extra_config.OptionValue
        for option in options:
            if (option.key.startswith('nvp.iface-id.') and
                option.value == iface_id):
                return int(option.key.split('.')[2])


def power_off_instance(session, instance, vm_ref=None):
    """Power off the specified instance."""

    if vm_ref is None:
        vm_ref = get_vm_ref(session, instance)

    LOG.debug("Powering off the VM", instance=instance)
    try:
        poweroff_task = session._call_method(session.vim,
                                         "PowerOffVM_Task", vm_ref)
        session._wait_for_task(poweroff_task)
        LOG.debug("Powered off the VM", instance=instance)
    except vexc.InvalidPowerStateException:
        LOG.debug("VM already powered off", instance=instance)


def find_rescue_device(hardware_devices, instance):
    """Returns the rescue device.

    The method will raise an exception if the rescue device does not
    exist. The resuce device has suffix '-rescue.vmdk'.
    :param hardware_devices: the hardware devices for the instance
    :param instance: nova.objects.instance.Instance object
    :return: the rescue disk device object
    """
    for device in hardware_devices.VirtualDevice:
        if (device.__class__.__name__ == "VirtualDisk" and
                device.backing.__class__.__name__ ==
                'VirtualDiskFlatVer2BackingInfo' and
                device.backing.fileName.endswith('-rescue.vmdk')):
            return device

    msg = _('Rescue device does not exist for instance %s') % instance.uuid
    raise exception.NotFound(msg)


def get_ephemeral_name(id):
    return 'ephemeral_%d.vmdk' % id


def _detach_and_delete_devices_config_spec(client_factory, devices):
    config_spec = client_factory.create('ns0:VirtualMachineConfigSpec')
    device_config_spec = []
    for device in devices:
        virtual_device_config = client_factory.create(
                                'ns0:VirtualDeviceConfigSpec')
        virtual_device_config.operation = "remove"
        virtual_device_config.device = device
        virtual_device_config.fileOperation = "destroy"
        device_config_spec.append(virtual_device_config)
    config_spec.deviceChange = device_config_spec
    return config_spec


def detach_devices_from_vm(session, vm_ref, devices):
    """Detach specified devices from VM."""
    client_factory = session.vim.client.factory
    config_spec = _detach_and_delete_devices_config_spec(
        client_factory, devices)
    reconfigure_vm(session, vm_ref, config_spec)


def get_ephemerals(session, vm_ref):
    devices = []
    hardware_devices = session._call_method(vim_util,
            "get_dynamic_property", vm_ref, "VirtualMachine",
            "config.hardware.device")


    if hardware_devices.__class__.__name__ == "ArrayOfVirtualDevice":
        hardware_devices = hardware_devices.VirtualDevice

    for device in hardware_devices:
        if device.__class__.__name__ == "VirtualDisk":
            if (device.backing.__class__.__name__ ==
                    "VirtualDiskFlatVer2BackingInfo"):
                if 'ephemeral' in device.backing.fileName:
                    devices.append(device)
    return devices


def get_swap(session, vm_ref):
    hardware_devices = session._call_method(vutil, "get_object_property",
                                            vm_ref, "config.hardware.device")

    if hardware_devices.__class__.__name__ == "ArrayOfVirtualDevice":
        hardware_devices = hardware_devices.VirtualDevice

    for device in hardware_devices:
        if (device.__class__.__name__ == "VirtualDisk" and
                device.backing.__class__.__name__ ==
                    "VirtualDiskFlatVer2BackingInfo" and
                'swap' in device.backing.fileName):
            return device


def _get_folder(session, parent_folder_ref, name):
    # Get list of child entities for the parent folder
    prop_val = session._call_method(vutil, 'get_object_property',
                                    parent_folder_ref,
                                    'childEntity')
    if prop_val:
        child_entities = prop_val.ManagedObjectReference

        # Return if the child folder with input name is already present
        for child_entity in child_entities:
            if child_entity._type != 'Folder':
                continue
            child_entity_name = vim_util.get_entity_name(session, child_entity)
            if child_entity_name == name:
                return child_entity


def create_folder(session, parent_folder_ref, name):
    """Creates a folder in vCenter

    A folder of 'name' will be created under the parent folder.
    The moref of the folder is returned.
    """

    folder = _get_folder(session, parent_folder_ref, name)
    if folder:
        return folder
    LOG.debug("Creating folder: %(name)s. Parent ref: %(parent)s.",
              {'name': name, 'parent': parent_folder_ref.value})
    try:
        folder = session._call_method(session.vim, "CreateFolder",
                                      parent_folder_ref, name=name)
        LOG.info(_LI("Created folder: %(name)s in parent %(parent)s."),
                 {'name': name, 'parent': parent_folder_ref.value})
    except vexc.DuplicateName as e:
        LOG.debug("Folder already exists: %(name)s. Parent ref: %(parent)s.",
                  {'name': name, 'parent': parent_folder_ref.value})
        val = e.details['object']
        folder = vutil.get_moref(val, 'Folder')
    return folder


def folder_ref_cache_update(path, folder_ref):
    _FOLDER_PATH_REF_MAPPING[path] = folder_ref


def folder_ref_cache_get(path):
    return _FOLDER_PATH_REF_MAPPING.get(path)


def _get_vm_name(display_name, id):
    if display_name:
        return '%s (%s)' % (display_name[:41], id[:36])
    else:
        return id[:36]


def rename_vm(session, vm_ref, instance):
    vm_name = _get_vm_name(instance.display_name, instance.uuid)
    rename_task = session._call_method(session.vim, "Rename_Task", vm_ref,
                                       newName=vm_name)
    session._wait_for_task(rename_task)

# Vsettan-only start live snapshot
def get_current_snapshot_from_vm_ref(session, vm_ref):
    # Get the id of current snapshot, if there is no snapshot
    # on the VM instance, will return None
    current_snapshot_property_name = 'snapshot.currentSnapshot'
    property_set = session._call_method(
            vim_util, "get_object_properties",
            None, vm_ref, vm_ref._type, [current_snapshot_property_name])
    current_snapshot = property_from_property_set(
        current_snapshot_property_name, property_set)
    if current_snapshot is not None:
        snapshot_id = current_snapshot.val.value
        LOG.debug("Find current snapshot %s of vm instance", snapshot_id)
        return snapshot_id


def get_snapshots_from_vm_ref(session, vm_ref):
    """This method allows you to find the snapshots of a VM.

    :param session: a vSphere API connection
    :param vm_ref: a reference object to the running VM
    :return: the list of InstanceSnapshot object
    """

    snapshot_list_property_name = 'snapshot.rootSnapshotList'
    property_set = session._call_method(
            vim_util, "get_object_properties",
            None, vm_ref, vm_ref._type, [snapshot_list_property_name])
    snapshot_id = get_current_snapshot_from_vm_ref(session, vm_ref)

    result = {}
    snapshot_list = property_from_property_set(
        snapshot_list_property_name, property_set)
    if snapshot_list is not None:
        for vmsnap in snapshot_list.val.VirtualMachineSnapshotTree:
            snapshots = build_snapshot_obj(snapshot_id, vmsnap)
            result.update(snapshots)

    LOG.debug("Got total of %s snapshots.", len(result))
    return result


def get_snapshot_obj_by_snapshot_ref(session, vm_ref, snapshot_ref):
    """This method is used to find the snapshot object via
    VirtualMachineSnapshot object.

    """
    all_snapshots = get_snapshots_from_vm_ref(session, vm_ref)
    for snap_ref in all_snapshots:
        if snap_ref.value == snapshot_ref.value:
            return all_snapshots[snap_ref]
    raise exception.NotFound(_("The snapshot %s can not be found")
                             % snapshot_ref.value)


def get_snapshot_ref_by_snapshot_id(session, vm_ref, snapshot_id):
    """This method is used to find the VirtualMachineSnapshot
    object via snapshot id.

    """
    all_snapshots = get_snapshots_from_vm_ref(session, vm_ref)
    for snap_ref in all_snapshots:
        snap_obj = all_snapshots[snap_ref]
        if str(snap_obj['snapshot_id']) == str(snapshot_id):
            return snap_ref
    raise exception.NotFound(_("The snapshot %s can not be found")
                             % snapshot_id)


def build_snapshot_obj(current_snapshot_id, vm_snapshot_tree):
    """This method is used to build instance_snapshot object from
    VMware VirtualMachineSnapshotTree data object.

    """
    result = {}
    snapshot = {}
    snapshot['snapshot_id'] = vm_snapshot_tree.id
    snapshot['name'] = vm_snapshot_tree.name
    snapshot['description'] = vm_snapshot_tree.description
    snapshot['create_time'] = vm_snapshot_tree.createTime

    snapshot_value = vm_snapshot_tree.snapshot.value
    snapshot['is_current_snapshot'] = (True if current_snapshot_id ==
        snapshot_value else False)

    snapshot['metadata'] = {}
    snapshot['metadata']['quiesced'] = vm_snapshot_tree.quiesced
    snapshot['metadata']['replaySupported'] = vm_snapshot_tree.replaySupported
    snapshot['metadata']['vm_state'] = vm_snapshot_tree.state
    snapshot['metadata']['snapshot_value'] = snapshot_value

    result[vm_snapshot_tree.snapshot] = snapshot
    LOG.debug("Find a snapshot: %(id)s----%(name)s",
              {'id': snapshot['snapshot_id'], 'name': snapshot['name']})
    if hasattr(vm_snapshot_tree, 'childSnapshotList'):
        for sp in vm_snapshot_tree.childSnapshotList:
            children = build_snapshot_obj(current_snapshot_id, sp)
            result.update(children)
    return result
# Vsettan-only stop live snapshot


# Vsettan-only start
def associate_alternate_uuid_for_instance(session, instance):
    """Associates a discovered VM to an instance using a newly generated UUID.

    1. Update the extraConfig property for nvp.vm-uuid to be replaced with
    a new UUID
    """

    vm_ref = get_vm_ref(session, instance)
    new_uuid = unicode(uuid.uuid4())
    instance['uuid'] = new_uuid

    extra_opts = {'nvp.vm-uuid': new_uuid}
    client_factory = session.vim.client.factory
    reconfig_spec = get_vm_extra_config_spec(client_factory, extra_opts)
    LOG.debug(_("Associating discovered VM to instance %s"), instance['uuid'],
               instance=instance)
    reconfig_task = session._call_method(session.vim, "ReconfigVM_Task",
                                         vm_ref, spec=reconfig_spec)
    session._wait_for_task(reconfig_task)
    LOG.debug(_("Associated discovered VM to instance %s"), instance['uuid'],
               instance=instance)

    # Return new UUID
    return new_uuid

def get_virtual_disks(hardware_devices):
    if hardware_devices.__class__.__name__ == "ArrayOfVirtualDevice":
        hardware_devices = hardware_devices.VirtualDevice

    return [ device for device in hardware_devices if device.__class__.__name__ == "VirtualDisk" ]


def property_from_property_set(property_name, property_set):
    '''Use this method to filter property collector results.

    Because network traffic is expensive, multiple
    VMwareAPI calls will sometimes pile-up properties
    to be collected. That means results may contain
    many different values for multiple purposes.

    This helper will filter a list for a single result
    and filter the properties of that result to find
    the single value of whatever type resides in that
    result. This could be a ManagedObjectReference ID
    or a complex value.

    :param property_name: name of property you want
    :param property_set: all results from query
    :return: the value of the property.
    '''

    for prop in property_set.objects:
        if hasattr(prop, 'propSet'): #Vsettan-only
            p = _property_from_propSet(prop.propSet, property_name)
            if p is not None:
                return p


def _property_from_propSet(propSet, name='name'):
    for p in propSet:
        if p.name == name:
            return p

def get_host_ref_from_name(session, host_name):
    """Get reference to the host with the name specified."""
    host_objs = session._call_method(vim_util, "get_objects",
                "HostSystem", ["name"])
    _cancel_retrieve_if_necessary(session, host_objs)
    return _get_object_from_results(session, host_objs,
                                            host_name,
                                            _get_object_for_value)
# Vsettan-only end
