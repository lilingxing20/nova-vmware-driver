# Copyright 2016 Vsettan Corp.
# Copyright (c) 2016 VMware, Inc.
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
Shared constants across the VMware driver
"""

from nova.network import model as network_model

# Vsettan-only (prs-related) start
# For ESXi host case
HYPERVISOR_IMAGE_TYPE = 'vmware_esx'
# Vsettan-only (prs-related) end

# Vsettan-only (windows sysprep constant) start

METADATA_TIME_ZONE = 'windows.timezone'

METADATA_WIN_WORKGOURP = 'windows.workgroup'
METADATA_WIN_DOMAINNAME = 'windows.domain.name'
METADATA_WIN_DOMAIN_USER = 'windows.domain.user'
METADATA_WIN_DOMAIN_PSWORD = 'windows.domain.password'

METADATA_WIN_COMPUTER_NAME = 'windows.computername'
METADATA_WIN_ORGANIZATION = 'windows.organization'
METADATA_WIN_PRODUCTKEY = 'windows.productkey'
METADATA_WIN_USERNAME = 'windows.username'

METADATA_WIN_PRI_WINS = 'networkdevice.%s.primaryWINS'
METADATA_WIN_SEC_WINS = 'networkdevice.%s.secondaryWINS'

# Vsettan-only (windows sysprep constant) end

# Vsettan-only (windows sysprep text constant) start
WIN_GUEST_PREFIX = 'win'

METADATA_WIN_OPTIONS_CHANGE_SID = 'change.sid'
METADATA_PSWORD = 'windows.admin.password'
METADATA_DNS_SUF = 'dns.suffix'
METADATA_NETWORK_DNS = 'networkdevice.%s.dns1'
METADATA_NETWORK_DNS2 = 'networkdevice.%s.dns2'
METADATA_NETWORK_IP = 'networkdevice.%s.ipaddress'
METADATA_NETWORK_MASK = 'networkdevice.%s.netmask'
METADATA_NETWORK_GATEWAY = 'networkdevice.%s.gateway1'
METADATA_NETWORK_GATEWAY2 = 'networkdevice.%s.gateway2'

METADATA_VALUE_FALSE = 'false'

METADATA_NETWORK_PREFIX = 'networkdevice'
METADATA_NETWORK_IP_SUFFIX = 'ipaddress'

SYSPREP_LOCAL_CONNECTION = 'Local Area Connection'
SYSPREP_LOCAL_CONNECTION_D = 'Local Area Connection %d'
SYSPREP_UNATTEN = 'unattend'
SYSPREP_IDENTIFIER = 'Identifier'
SYSPREP_SETTINGS = 'settings'
SYSPREP_PASS = 'pass'
SYSPREP_SPECIALIZE = 'specialize'
SYSPREP_COMP = 'component'
SYSPREP_NAME = 'name'
SYSPREP_TCPIP = 'Microsoft-Windows-TCPIP'
SYSPREP_DNS_CLIENT = 'Microsoft-Windows-DNS-Client'
SYSPREP_DNS_DOMAIN = 'DNSDomain'
SYSPREP_GATEWAY = 'NextHopAddress'
SYSPREP_DNS_SEARCH = 'DNSServerSearchOrder'
SYSPREP_IP = 'IpAddress'
SYSPREP_VALUE = 'Value'
SYSPREP_ADMIN_PSWORD = 'AdministratorPassword'
SYSPREP_DHCP_ENABLED = 'DhcpEnabled'
SYSPREP_ROUTES = 'Routes'
SYSPREP_INTERFACES = 'Interfaces'
SYSPREP_INTERFACE = 'Interface'
SYSPREP_UNICAST_IP = 'UnicastIpAddresses'

# Vsettan-only (windows sysprep text constant) end

MIN_VC_VERSION = '5.1.0'
# The minimum VC version for Neutron 'ovs' port type support
MIN_VC_OVS_VERSION = '5.5.0'

DISK_FORMAT_ISO = 'iso'
DISK_FORMAT_VHD = 'vhd'     # Vsettan-ONLY
DISK_FORMAT_VMDK = 'vmdk'
DISK_FORMAT_ISCSI = 'iscsi'
DISK_FORMATS_ALL = [DISK_FORMAT_ISO, DISK_FORMAT_VHD, DISK_FORMAT_VMDK]

DISK_TYPE_THIN = 'thin'
CONTAINER_FORMAT_BARE = 'bare'
CONTAINER_FORMAT_OVA = 'ova'
CONTAINER_FORMATS_ALL = [CONTAINER_FORMAT_BARE, DISK_FORMAT_VMDK]

DISK_TYPE_SPARSE = 'sparse'
DISK_TYPE_PREALLOCATED = 'preallocated'
DISK_TYPE_STREAM_OPTIMIZED = 'streamOptimized'
DISK_TYPE_EAGER_ZEROED_THICK = 'eagerZeroedThick'

DATASTORE_TYPE_VMFS = 'VMFS'
DATASTORE_TYPE_NFS = 'NFS'
DATASTORE_TYPE_NFS41 = 'NFS41'
DATASTORE_TYPE_VSAN = 'vsan'

DEFAULT_VIF_MODEL = network_model.VIF_MODEL_E1000
DEFAULT_OS_TYPE = "otherGuest"
DEFAULT_ADAPTER_TYPE = "lsiLogic"
DEFAULT_DISK_TYPE = DISK_TYPE_PREALLOCATED
DEFAULT_DISK_FORMAT = DISK_FORMAT_VMDK
DEFAULT_CONTAINER_FORMAT = CONTAINER_FORMAT_BARE

IMAGE_VM_PREFIX = "OSTACK_IMG"
SNAPSHOT_VM_PREFIX = "OSTACK_SNAP"

ADAPTER_TYPE_BUSLOGIC = "busLogic"
ADAPTER_TYPE_IDE = "ide"
ADAPTER_TYPE_LSILOGICSAS = "lsiLogicsas"
ADAPTER_TYPE_PARAVIRTUAL = "paraVirtual"

SUPPORTED_FLAT_VARIANTS = ["thin", "preallocated", "thick", "eagerZeroedThick"]

EXTENSION_KEY = 'org.openstack.compute'
EXTENSION_TYPE_INSTANCE = 'instance'

# The max number of devices that can be connnected to one adapter
# One adapter has 16 slots but one reserved for controller
SCSI_MAX_CONNECT_NUMBER = 15

# This list was extracted from the installation iso image for ESX 6.0.
# It is contained in s.v00, which is gzipped. The list was obtained by
# searching for the string 'otherGuest' in the uncompressed contents of that
# file, copying out the full list less the 'family' ids at the end, and sorting
# it. The contents of this list should be updated whenever there is a new
# release of ESX.
VALID_OS_TYPES = set([
    'asianux3_64Guest',
    'asianux3Guest',
    'asianux4_64Guest',
    'asianux4Guest',
    'asianux5_64Guest',
    'centos64Guest',
    'centosGuest',
    'coreos64Guest',
    'darwin10_64Guest',
    'darwin10Guest',
    'darwin11_64Guest',
    'darwin11Guest',
    'darwin12_64Guest',
    'darwin13_64Guest',
    'darwin14_64Guest',
    'darwin64Guest',
    'darwinGuest',
    'debian4_64Guest',
    'debian4Guest',
    'debian5_64Guest',
    'debian5Guest',
    'debian6_64Guest',
    'debian6Guest',
    'debian7_64Guest',
    'debian7Guest',
    'debian8_64Guest',
    'debian8Guest',
    'dosGuest',
    'eComStation2Guest',
    'eComStationGuest',
    'fedora64Guest',
    'fedoraGuest',
    'freebsd64Guest',
    'freebsdGuest',
    'genericLinuxGuest',
    'mandrakeGuest',
    'mandriva64Guest',
    'mandrivaGuest',
    'netware4Guest',
    'netware5Guest',
    'netware6Guest',
    'nld9Guest',
    'oesGuest',
    'openServer5Guest',
    'openServer6Guest',
    'opensuse64Guest',
    'opensuseGuest',
    'oracleLinux64Guest',
    'oracleLinuxGuest',
    'os2Guest',
    'other24xLinux64Guest',
    'other24xLinuxGuest',
    'other26xLinux64Guest',
    'other26xLinuxGuest',
    'other3xLinux64Guest',
    'other3xLinuxGuest',
    'otherGuest',
    'otherGuest64',
    'otherLinux64Guest',
    'otherLinuxGuest',
    'redhatGuest',
    'rhel2Guest',
    'rhel3_64Guest',
    'rhel3Guest',
    'rhel4_64Guest',
    'rhel4Guest',
    'rhel5_64Guest',
    'rhel5Guest',
    'rhel6_64Guest',
    'rhel6Guest',
    'rhel7_64Guest',
    'rhel7Guest',
    'sjdsGuest',
    'sles10_64Guest',
    'sles10Guest',
    'sles11_64Guest',
    'sles11Guest',
    'sles12_64Guest',
    'sles12Guest',
    'sles64Guest',
    'slesGuest',
    'solaris10_64Guest',
    'solaris10Guest',
    'solaris11_64Guest',
    'solaris6Guest',
    'solaris7Guest',
    'solaris8Guest',
    'solaris9Guest',
    'suse64Guest',
    'suseGuest',
    'turboLinux64Guest',
    'turboLinuxGuest',
    'ubuntu64Guest',
    'ubuntuGuest',
    'unixWare7Guest',
    'vmkernel5Guest',
    'vmkernel6Guest',
    'vmkernelGuest',
    'win2000AdvServGuest',
    'win2000ProGuest',
    'win2000ServGuest',
    'win31Guest',
    'win95Guest',
    'win98Guest',
    'windows7_64Guest',
    'windows7Guest',
    'windows7Server64Guest',
    'windows8_64Guest',
    'windows8Guest',
    'windows8Server64Guest',
    'windows9_64Guest',
    'windows9Guest',
    'windows9Server64Guest',
    'windowsHyperVGuest',
    'winLonghorn64Guest',
    'winLonghornGuest',
    'winMeGuest',
    'winNetBusinessGuest',
    'winNetDatacenter64Guest',
    'winNetDatacenterGuest',
    'winNetEnterprise64Guest',
    'winNetEnterpriseGuest',
    'winNetStandard64Guest',
    'winNetStandardGuest',
    'winNetWebGuest',
    'winNTGuest',
    'winVista64Guest',
    'winVistaGuest',
    'winXPHomeGuest',
    'winXPPro64Guest',
    'winXPProGuest',
])
