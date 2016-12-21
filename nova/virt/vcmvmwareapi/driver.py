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
A connection to the VMware vCenter platform.
"""

import re

from oslo_serialization import jsonutils
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import excutils
from oslo_utils import versionutils as v_utils
from oslo_vmware import api
from oslo_vmware import exceptions as vexc
from oslo_vmware import pbm
from oslo_vmware import vim
from oslo_vmware import vim_util

from nova.compute import task_states
import nova.conf
from nova import exception
from nova.i18n import _, _LI, _LE, _LW
from nova.virt import driver

from nova import context as nova_context
from nova import objects as nova_objects

from nova.virt.vcmvmwareapi import ds_util
from nova.virt.vcmvmwareapi import constants
from nova.virt.vcmvmwareapi import error_util
from nova.virt.vcmvmwareapi import host as vcm_host
from nova.virt.vcmvmwareapi import vim_util as vcm_vim_util
from nova.virt.vcmvmwareapi import vm_util
from nova.virt.vcmvmwareapi import vmops
from nova.virt.vcmvmwareapi import volumeops
from nova.virt.vcmvmwareapi import network_util

LOG = logging.getLogger(__name__)

vmwareapi_opts = [
    cfg.StrOpt('host_ip',
               help='Hostname or IP address for connection to VMware '
                    'vCenter host.'),
    cfg.PortOpt('host_port',
                default=443,
                help='Port for connection to VMware vCenter host.'),
    cfg.StrOpt('host_username',
               help='Username for connection to VMware vCenter host.'),
    cfg.StrOpt('host_password',
               help='Password for connection to VMware vCenter host.',
               secret=True),
    cfg.StrOpt('ca_file',
               help='Specify a CA bundle file to use in verifying the '
                    'vCenter server certificate.'),
    cfg.BoolOpt('insecure',
                default=False,
                help='If true, the vCenter server certificate is not '
                     'verified. If false, then the default CA truststore is '
                     'used for verification. This option is ignored if '
                     '"ca_file" is set.'),
    cfg.StrOpt('cluster_name',
               help='Name of a VMware Cluster ComputeResource.'),
    cfg.StrOpt('datastore_regex',
               help='Regex to match the name of a datastore.'),
    cfg.FloatOpt('task_poll_interval',
                 default=0.5,
                 help='The interval used for polling of remote tasks.'),
    cfg.IntOpt('api_retry_count',
               default=10,
               help='The number of times we retry on failures, e.g., '
                    'socket error, etc.'),
    cfg.PortOpt('vnc_port',
                default=5900,
                help='VNC starting port'),
    cfg.IntOpt('vnc_port_total',
               default=10000,
               help='Total number of VNC ports'),
    cfg.BoolOpt('use_linked_clone',
                default=True,
                help='Whether to use linked clone'),
    #Vsettan vm name for vCenter BEGIN
    cfg.BoolOpt('use_displayname_uuid_for_vmname',
                default=False,
                help='Whether display_name is included in the VM name. '
                      'If True, vCenter VM name is in format of display_name-uuid; '
                      'otherwise, the VM name is simply uuid.'),
    #Vsettan vm name for vCenter END
    #Vsettan Resource Pool BEGIN
    cfg.StrOpt('resource_pool',
               default=None,
               help='Name of a VMware resource pool. Used together with'
               'cluster_name. If the user specifies a cluster name and a'
               'resource pool name, it means the resource pool under the'
               'cluster is the target to deploy the VM.'),
    #Vsettan Resource Pool END
    # Vsettan-only (prs-related) start
    cfg.StrOpt('esx_host_name',
               default=None,
               help='Host name or IP of VMware ESXi host.'),
    # Vsettan-only (prs-related) end
    # Vsettan-only begin
    cfg.StrOpt('datastore_cluster_name',
               help='Name of a VMware Datastore Cluster. '
                    'Used only if compute_driver is '
                    'vcmvmwareapi.VCMVMwareVCDriver.'),
    cfg.BoolOpt('use_sdrs',
               help='Use Storage DRS.'
                    'default=False'
                    'Used only if compute_driver is '
                    'vcmvmwareapi.VCMVMwareVCDriver.'),
    cfg.BoolOpt('random_datastore',
                 default=False,
                 help='If True then will randomly chose a datastore from'
                      ' available list'),
    # Vsettan-only end
    # Vsettan-ONLY START snapshot to template
    cfg.StrOpt('snapshot_image_format',
               default='vmdk',
               help='snapshot_image_format = vmdk or template'),
    # Vsettan-ONLY STOP
    # Vsettan-only hot resize begin
    cfg.BoolOpt('enable_vm_hot_resize',
                default=True,
                help='True to enable hot resize. If hot resize is enabled, '
                     'and all the hot resize related VM settings in VCenter '
                     'are True, vmware driver will resize the VM without '
                     'rebooting it. The VM settings related to hot resize '
                     'includes: '
                     'VirtualMachineConfigSpec.cpuHotAddEnabled, '
                     'VirtualMachineConfigSpec.memoryHotAddEnabled.'
                ),
    cfg.BoolOpt('strict_resize_memory',
                default=True,
                help='True to strictly resize memory according to new flavor. '
                     'If "memoryHotAddEnabled" is True, the memory increase '
                     'must be a multiple of "hotPlugMemoryIncrementSize", '
                     ' which is virtual machine setting in VCener. '
                     'If this option equeals True, and the memory increase '
                     'specified by flavor is not multiple of '
                     '"hotPlugMemoryIncrementSize", vmware driver will do '
                     'cold resize. If this option is False, driver will do '
                     'hot resize, and make increased memory size to be '
                     'approximately equals to the memory size specified by '
                     'flavor.'
                ),
    # Vsettan-only hot resize end
    # Vsettan-only external dhcp start
    cfg.IntOpt('external_dhcp_retry_count',
               default=10,
               help='The number of times we retry on obtaining ip address '
                    'via vmware tools'),
    cfg.IntOpt('external_dhcp_interval',
               default=10,
               help='The time interval we retry to query the guest ip address'
               ),
    cfg.IntOpt('time_wait_for_ip_matching',
               default=120,
               help='The time we need to wait for the guest ip equals to the injected ip'
               ),
    # Vsettan-only external dhcp end
    # Vsettan-only metadata customization start
    cfg.StrOpt('domain_name',
               default='vcm-domainname',
               help='The domain name needed to specify to customize the spec'
               ),
    cfg.StrOpt('dns_suffix',
               default='vcm.cn.Vsettan.com',
               help='The dns suffix needed to specify to customize the spec'
               ),
    cfg.StrOpt('workgroup',
               default='WORKGROUP',
               help='The workgroup needed to specify to customize the spec'
               'if no workgroup and domain are specified with metadata'
               ),
    cfg.StrOpt('timezone',
               default=90,
               help='The timezone needed to specify to customize the spec'
               'if no zone time is specified with metadata'
               ),
    cfg.StrOpt('organization_name',
               default='Vsettan.com',
               help='The organization name needed to specify to customize the spec'
               'if no organization name is specified with metadata'
               ),
    cfg.StrOpt('product_key',
               default='',
               help='The product key needed to specify to customize the spec'
               'if no product key is specified with metadata'
               ),
    cfg.StrOpt('user_name',
               default='Vsettan',
               help='The user name needed to specify to customize the spec'
               'if no user name is specified with metadata'
               ),
    cfg.StrOpt('customization_enabled',
               default=True,
               help='The customization_enabled need to be enabled for customization function'
               ),
    # Vsettan-only metadata customization end
    cfg.StrOpt('wsdl_location',
               help='Optional VIM Service WSDL Location '
                    'e.g http://<server>/vimService.wsdl. '
                    'Optional over-ride to default location for bug '
                    'work-arounds')
    ]

spbm_opts = [
    cfg.BoolOpt('pbm_enabled',
                default=False,
                help='The PBM status.'),
    cfg.StrOpt('pbm_wsdl_location',
               help='PBM service WSDL file location URL. '
                    'e.g. file:///opt/SDK/spbm/wsdl/pbmService.wsdl '
                    'Not setting this will disable storage policy based '
                    'placement of instances.'),
    cfg.StrOpt('pbm_default_policy',
               help='The PBM default policy. If pbm_wsdl_location is set and '
                    'there is no defined storage policy for the specific '
                    'request then this policy will be used.'),
    ]

CONF = nova.conf.CONF
CONF.register_opts(vmwareapi_opts, 'vmware')
CONF.register_opts(spbm_opts, 'vmware')

TIME_BETWEEN_API_CALL_RETRIES = 1.0


class VCMVMwareVCDriver(driver.ComputeDriver):
    """The VC host connection object."""

    capabilities = {
        "has_imagecache": True,
        "supports_recreate": False,
        "supports_migrate_to_same_host": True
    }

    # Legacy nodename is of the form: <mo id>(<cluster name>)
    # e.g. domain-26(TestCluster)
    # We assume <mo id> consists of alphanumeric, _ and -.
    # We assume cluster name is everything between the first ( and the last ).
    # We pull out <mo id> for re-use.
    LEGACY_NODENAME = re.compile('([\w-]+)\(.+\)')

    # The vCenter driver includes API that acts on ESX hosts or groups
    # of ESX hosts in clusters or non-cluster logical-groupings.
    #
    # vCenter is not a hypervisor itself, it works with multiple
    # hypervisor host machines and their guests. This fact can
    # subtly alter how vSphere and OpenStack interoperate.

    def __init__(self, virtapi, scheme="https"):
        super(VCMVMwareVCDriver, self).__init__(virtapi)

        if (CONF.vmware.host_ip is None or
            CONF.vmware.host_username is None or
            CONF.vmware.host_password is None):
            raise Exception(_("Must specify host_ip, host_username and "
                              "host_password to use vcmvmwareapi.VCMVMwareVCDriver"))

        self._datastore_regex = None
        if CONF.vmware.datastore_regex:
            try:
                self._datastore_regex = re.compile(CONF.vmware.datastore_regex)
            except re.error:
                raise exception.InvalidInput(reason=
                    _("Invalid Regular Expression %s")
                    % CONF.vmware.datastore_regex)

        self._session = VMwareAPISession(scheme=scheme)

        self._check_min_version()

        # Update the PBM location if necessary
        if CONF.vmware.pbm_enabled:
            self._update_pbm_location()

        self._validate_configuration()
        self._cluster_name = CONF.vmware.cluster_name

        #Vsettan Resource Pool BEGIN
        # Get the resource pool, the path consists of the cluster
        # or host name and the resource pool name with a colon as
        # the delimiter.
        self._res_pool_path = CONF.vmware.resource_pool
        self._host = None
        self._res_pool_name = None
        self._res_pool_mor = None
        if self._res_pool_path:
            host_or_cluster = self._res_pool_path.split(":")[0]
            self._res_pool_name = self._res_pool_path.split(":")[-1]
            # If the name before the colon does not exist in the
            # cluster names, then we know this name is a host name.
            if self._cluster_name is None or host_or_cluster != self._cluster_name:
                LOG.warning(_("The resource pool location '%s' is not equal to "
                              "the specified cluster, so it's supposed to be "
                              "a esxi host."), host_or_cluster)
                self._host = host_or_cluster
            # Otherwise, it is a cluster name.
            #else:
            #    self._cluster_name = host_or_cluster

        # If ESXi host is specified, driver will use root resource pool under the host
        vmware_esx_host = CONF.vmware.esx_host_name
        if vmware_esx_host and self._host is None:
            self._host = vmware_esx_host
            self._res_pool_path = vmware_esx_host
        self._perf_counter_id_lookup_map = None

        # If the resource pool under a host is specified, we will use the pool
        # under the host only.
        self._host_mor = None
        self._cluster_mor = None
        if self._res_pool_name:
            if self._host:
                (self._res_pool_mor, self._host_mor) = vm_util.get_pool_refs_by_host(
                                                                self._session,
                                                                self._host,
                                                                self._res_pool_name)
                if not self._res_pool_mor:
                    raise exception.NotFound(_("Resource pool %(resourcepool)s was not"
                                               " found on host %(host)s")
                                             % {"resourcepool": self._res_pool_mor,
                                                "host": self._host})
            elif self._cluster_name:
                (self._res_pool_mor, self._cluster_mor) = vm_util.get_pool_refs_by_cluster(
                                                                   self._session,
                                                                   self._cluster_name,
                                                                   self._res_pool_name)
                if not self._res_pool_mor:
                    raise exception.NotFound(_("Resource pool %(resourcepool)s was not"
                                               " found on cluster %(cluster)s")
                                             % {"resourcepool": self._res_pool_mor,
                                                "cluster": self._cluster_name})
        else:
            self._cluster_mor = vm_util.get_cluster_ref_by_name(self._session,
                                                                self._cluster_name)
            if self._cluster_mor is None:
                raise exception.NotFound(_("The specified cluster '%s' was not "
                                           "found in vCenter")
                                         % self._cluster_name)
        # Check if the datastore cluster specified in the nova.conf is in the
        # vCenter. If it is not there, log a warning.
        self._storage_pod = None
        storage_pod_name = CONF.vmware.datastore_cluster_name
        if storage_pod_name:
            self._storage_pod = ds_util.get_storage_pod_ref_by_name(self._session,
                                                                storage_pod_name)
            if self._storage_pod is None:
                LOG.warn(_("StoragePod %s is not found") % storage_pod_name)

        #Vsettan Resource Pool BEGIN
        self._virtapi = virtapi
        if self._res_pool_mor:
            self._nodename = self._res_pool_path
            self._volumeops = volumeops.VMwareVolumeOps(self._session,
                                                   self._cluster_mor,
                                                   self._host_mor,
                                                   resource_pool=self._res_pool_mor)
            self._vmops = vmops.VMwareVMOps(self._session, self._virtapi,
                                       self._volumeops,
                                       self._cluster_mor, self._host_mor,
                                       datastore_regex=self._datastore_regex,
                                       res_pool=self._res_pool_mor,
                                       storage_pod=self._storage_pod,
                                       nodename=self._nodename)
            self._vc_state = vcm_host.VCState(self._session, self._res_pool_path,
                                     self._cluster_mor, self._host_mor,
                                     resource_pool=self._res_pool_mor,
                                     datastore_regex=self._datastore_regex, #Vsettan-only
                                     storage_pod=self._storage_pod) #Vsettan-only
            LOG.info(_("Resource pool name is %s."), self._res_pool_name)
        #Vsettan Resource Pool END
        else:
            self._nodename = self._create_nodename(self._cluster_mor.value, 
                                             self._cluster_name)
            self._volumeops = volumeops.VMwareVolumeOps(self._session,
                                        self._cluster_mor)
            self._vmops = vmops.VMwareVMOps(self._session, self._virtapi,
                                       self._volumeops,
                                       self._cluster_mor,
                                       # Vsettan-only begin
                                       storage_pod=self._storage_pod,
                                       nodename=self._nodename,
                                       # Vsettan-only end
                                       datastore_regex=self._datastore_regex)
            self._vc_state = vcm_host.VCState(self._session, self._nodename,
                                     self._cluster_mor,
                                     datastore_regex=self._datastore_regex,
                                     storage_pod=self._storage_pod) #Vsettan-only
            LOG.info(_("Cluster_name is %s."), self._cluster_name)

        LOG.info(_("self.get_host_stats is %s."), self._vc_state.get_host_stats())
        '''raise exception.NotFound("All clusters specified %s were not"
                                           " found in the vCenter")'''

        # Register the OpenStack extension
        self._register_openstack_extension()

    def _check_min_version(self):
        min_version = v_utils.convert_version_to_int(constants.MIN_VC_VERSION)
        vc_version = vim_util.get_vc_version(self._session)
        LOG.info(_LI("VMware vCenter version: %s"), vc_version)
        if min_version > v_utils.convert_version_to_int(vc_version):
            # TODO(garyk): enforce this from M
            LOG.warning(_LW('Running Nova with a VMware vCenter version less '
                            'than %(version)s is deprecated. The required '
                            'minimum version of vCenter will be raised to '
                            '%(version)s in the 13.0.0 release.'),
                        {'version': constants.MIN_VC_VERSION})

    @property
    def need_legacy_block_device_info(self):
        return False

    def _update_pbm_location(self):
        if CONF.vmware.pbm_wsdl_location:
            pbm_wsdl_loc = CONF.vmware.pbm_wsdl_location
        else:
            version = vim_util.get_vc_version(self._session)
            pbm_wsdl_loc = pbm.get_pbm_wsdl_location(version)
        self._session.pbm_wsdl_loc_set(pbm_wsdl_loc)

    def _validate_configuration(self):
        if CONF.vmware.use_linked_clone is None:
            raise vexc.UseLinkedCloneConfigurationFault()

        if CONF.vmware.pbm_enabled:
            if not CONF.vmware.pbm_default_policy:
                raise error_util.PbmDefaultPolicyUnspecified()
            if not pbm.get_profile_id_by_name(
                            self._session,
                            CONF.vmware.pbm_default_policy):
                raise error_util.PbmDefaultPolicyDoesNotExist()
            if CONF.vmware.datastore_regex:
                LOG.warning(_LW(
                    "datastore_regex is ignored when PBM is enabled"))
                self._datastore_regex = None

    def init_host(self, host):
        # Vsettan-only start hot resize
        self.host = host
        # Vsettan-only stop hot resize
        vim = self._session.vim
        if vim is None:
            self._session._create_session()

    def cleanup_host(self, host):
        self._session.logout()

    def _register_openstack_extension(self):
        # Register an 'OpenStack' extension in vCenter
        LOG.debug('Registering extension %s with vCenter',
                  constants.EXTENSION_KEY)
        os_extension = self._session._call_method(vim_util, 'find_extension',
                                                  constants.EXTENSION_KEY)
        if os_extension is None:
            LOG.debug('Extension does not exist. Registering type %s.',
                      constants.EXTENSION_TYPE_INSTANCE)
            self._session._call_method(vim_util, 'register_extension',
                                       constants.EXTENSION_KEY,
                                       constants.EXTENSION_TYPE_INSTANCE)

    def cleanup(self, context, instance, network_info, block_device_info=None,
                destroy_disks=True, migrate_data=None, destroy_vifs=True):
        """Cleanup after instance being destroyed by Hypervisor."""
        pass

    def resume_state_on_host_boot(self, context, instance, network_info,
                                  block_device_info=None):
        """resume guest state when a host is booted."""
        # Check if the instance is running already and avoid doing
        # anything if it is.
        state = vm_util.get_vm_state(self._session, instance)
        ignored_states = ['poweredon', 'suspended']
        if state.lower() in ignored_states:
            return
        # Instance is not up and could be in an unknown state.
        # Be as absolute as possible about getting it back into
        # a known and running state.
        self.reboot(context, instance, network_info, 'hard',
                    block_device_info)

    def list_instance_uuids(self):
        """List VM instance UUIDs."""
        return self._vmops.list_instances()

    def list_instances(self):
        """List VM instances from the single compute node."""
        return self._vmops.list_instances()

    def migrate_disk_and_power_off(self, context, instance, dest,
                                   flavor, network_info,
                                   block_device_info=None,
                                   timeout=0, retry_interval=0):
        """Transfers the disk of a running instance in multiple phases, turning
        off the instance before the end.
        """
        # Vsettan-only start hot resize
        if instance['host'] == self.host:
            doable, new_mem = self._vmops._hot_resize_doable(instance, flavor)
            if doable:
                self._vmops.prepare_hot_resize(context, instance, dest, flavor)
                # Pass hot resize info to finish_migrate() thread via disk_info
                resize_info = {'hot_resize': True, 'new_mem': new_mem}
                return jsonutils.dumps(resize_info)
        # Vsettan-only stop hot resize
        # TODO(PhilDay): Add support for timeout (clean shutdown)
        return self._vmops.migrate_disk_and_power_off(context, instance,
                                                      dest, flavor)

    def confirm_migration(self, migration, instance, network_info):
        """Confirms a resize, destroying the source VM."""
        self._vmops.confirm_migration(migration, instance, network_info)

    def finish_revert_migration(self, context, instance, network_info,
                                block_device_info=None, power_on=True):
        """Finish reverting a resize, powering back on the instance."""
        self._vmops.finish_revert_migration(context, instance, network_info,
                                            block_device_info, power_on)

    def finish_migration(self, context, migration, instance, disk_info,
                         network_info, image_meta, resize_instance,
                         block_device_info=None, power_on=True):
        """Completes a resize, turning on the migrated instance."""
        # Vsettan-only start hot resize
        if resize_instance and disk_info:
            resize_info = jsonutils.loads(disk_info)
            hot_resize = resize_info.get('hot_resize')
            new_mem = resize_info.get('new_mem')
            if hot_resize:
                if new_mem:
                    instance.memory_mb = new_mem
                self._vmops.finish_hot_resize(context, migration, instance,
                                        disk_info, network_info, image_meta,
                                        block_device_info=None)
                # Mark this instance, so that compute manager will know it
                # is hot resized and will confirm resize automatically.
                instance.system_metadata['vcm_hot_resize'] = True
                return
        # Vsettan-only stop hot resize
        self._vmops.finish_migration(context, migration, instance, disk_info,
                                     network_info, image_meta, resize_instance,
                                     block_device_info, power_on)

    # Vsettan-only (prs-related) begin
    def check_can_live_migrate_destination(self, context, instance,
                                           src_compute_info, dst_compute_info,
                                           block_migration=False,
                                           disk_over_commit=False):
        """Check if it is possible to execute live migration.

        This runs checks on the destination host, and then calls
        back to the source host to check the results.

        :param context: security context
        :param instance: nova.db.sqlalchemy.models.Instance
        :param block_migration: if true, prepare for block migration
        :param disk_over_commit: if true, allow disk over commit
        :returns: a dict containing:
             :filename: name of the tmpfile under CONF.instances_path
             :block_migration: whether this is block migration
             :disk_over_commit: disk-over-commit factor on dest host
             :disk_available_mb: available disk space on dest host
        """
        disk_available_mb = None
        if block_migration:
            disk_available_gb = dst_compute_info['disk_available_least']
            disk_available_mb = \
                      (disk_available_gb * units.Ki) - CONF.reserved_host_disk_mb

        host_name = dst_compute_info['hypervisor_hostname']

        # Compare migration compatibility
        self._check_migrate_compatibile(instance, host_name)

        # Check whether destination host has same datastore with instance
        self._check_datastore_exist(instance, host_name)

        image_type = 'vmdk'
        if instance is not None:
            system_metadata = instance.get('system_metadata')
            image_type = system_metadata['image_disk_format']

        return {"filename": "",
                "image_type": image_type,
                "disk_over_commit": disk_over_commit,
                "disk_available_mb": disk_available_mb}

    def _check_migrate_compatibile(self, instance, host_name):
        """Check live migration destination host's compatibility"""
        vm_ref = vm_util.get_vm_ref(self._session, instance)
        (pool_ref, host_ref) = vm_util.get_pool_refs_by_host(self._session, host_name)
        compatibilityChecker = self._session.vim.service_content.vmProvisioningChecker
        try:
            compatibility_task = self._session._call_method(
                                      self._session.vim,
                                      "CheckMigrate_Task", compatibilityChecker,
                                      vm=vm_ref,
                                      host=host_ref,
                                      pool=pool_ref)
            task_info = self._session._wait_for_task(compatibility_task)
        except Exception as excep:
             LOG.warning(_LW("Migration compatibility check fail due to: %s"),
                         excep)

        compatibilityChecker_result = task_info.result.CheckResult[0]
        if hasattr(compatibilityChecker_result, 'error'):
            for e in compatibilityChecker_result.error:
                fault_name = e.fault.__class__.__name__
                if fault_name == 'CpuIncompatible1ECX':
                    m = _("CPU doesn't have compatibility.\n\n%(ret)s\n\n")
                    raise exception.InvalidCPUInfo(reason=m % {'ret':
                                                               e.localizedMessage})
                elif fault_name == 'DisallowedMigrationDeviceAttached':
                    caused_fault = e.fault.fault
                    if (caused_fault.fault.__class__.__name__ ==
                        'FileBackedPortNotSupported'):
                        LOG.warning(_LW("Detach serial port because: %s"),
                                    e.localizedMessage)
                        vm_util.detach_serial_port(self._session, instance)
                elif (fault_name == 'VMotionNotConfigured' or
                      fault_name == 'VMotionNotSupported' or
                      fault_name == 'VMotionLinkDown'):
                    raise error_util.VMotionInterfaceException(param=e.localizedMessage)
                else:
                    raise exception.NovaException(_("An unknown exception occurred: %s")
                                                  % e.localizedMessage)

    def _check_datastore_exist(self, instance, host_name):
        """Check datastore required by instance be existed on host or not"""
        vm_ref = vm_util.get_vm_ref(self._session, instance)
        host_ref = vm_util.get_host_ref_from_name(self._session, host_name)
        datastores_on_host = ds_util.get_available_datastores(self._session,
                                                              host=host_ref,
                                                              datastore_regex=self._datastore_regex)
        ds_ref_ret = self._session._call_method(vimUtil, "get_dynamic_property",
                                                vm_ref, "VirtualMachine", "datastore")
        datastore_on_instance = self._session._call_method(vimUtil,
                                                           "get_properties_for_a_collection_of_objects",
                                                           "Datastore",
                                                           ds_ref_ret.ManagedObjectReference,
                                                           ["summary.name"])
        ds_name = datastore_on_instance.objects[0].propSet[0].val
        ds_existed = False
        for ds in datastores_on_host:
            if ds.name == ds_name:
                ds_existed = True
                break
        if not ds_existed:
            raise exception.DatastoreNotFound(_("Shared storage %(ds_name)s"
                                                " not existed or not configured"
                                                " with host %(host_name)s") 
                                              % {"ds_name": ds_name,
                                                 "host_name": host_name})
        return ds_existed

    def check_can_live_migrate_destination_cleanup(self, context,
                                                   dest_check_data):
        """Do required cleanup on dest host after check_can_live_migrate calls

        :param context: security context
        """
        pass

    def check_can_live_migrate_source(self, context, instance,
                                      dest_check_data,
                                      block_device_info=None):
        """Check if it is possible to execute live migration.

        This checks if the live migration can succeed, based on the
        results from check_can_live_migrate_destination.

        :param context: security context
        :param instance: nova.db.sqlalchemy.models.Instance
        :param dest_check_data: result of check_can_live_migrate_destination
        :param block_device_info: result of _get_instance_block_device_info
        :returns: a dict containing migration info
        """
        # Checking shared storage connectivity
        source = self.host

        dest_check_data.update({'is_shared_instance_path':
                self._check_datastore_exist(instance, source)})

        if not dest_check_data['is_shared_instance_path']:
            reason = _("Live migration can not be used "
                       "without shared storage.")
            raise exception.InvalidSharedStorage(reason=reason, path=source)

        return dest_check_data

    def ensure_filtering_rules_for_instance(self, instance, network_info):
        pass

    def unfilter_instance(self, instance, network_info):
        pass

    def pre_live_migration(self, context, instance, block_device_info,
                           network_info, disk_info, migrate_data=None):
        """Preparation live migration."""
        res_data = {'graphics_listen_addrs': {}}
        res_data['graphics_listen_addrs']['vnc'] = CONF.vncserver_listen
        res_data['graphics_listen_addrs']['spice'] = CONF.spice.server_listen

        return res_data

    def post_live_migration_at_destination(self, context,
                                           instance,
                                           network_info,
                                           block_migration=False,
                                           block_device_info=None):
        """Post operation of live migration at destination host.

        :param context: security context
        :param instance:
            nova.db.sqlalchemy.models.Instance object
            instance object that is migrated.
        :param network_info: instance network information
        :param block_migration: if true, post operation of block_migration.
        """
        pass

    # The following four functions are used for cpu_monitor
    def _init_perf_counter_id_lookup_map(self):
        """Query details of all the performance counters from VC"""
        session = self._session
        client_factory = session.vim.client.factory
        perf_manager = session.vim.service_content.perfManager

        prop_spec = vim_util.build_property_spec(
            client_factory, "PerformanceManager", ["perfCounter"])

        obj_spec = vim_util.build_object_spec(
            client_factory, perf_manager, None)

        filter_spec = vim_util.build_property_filter_spec(
            client_factory, [prop_spec], [obj_spec])

        options = client_factory.create('ns0:RetrieveOptions')
        options.maxObjects = 1

        prop_collector = session.vim.service_content.propertyCollector
        result = session.invoke_api(session.vim, "RetrievePropertiesEx",
                                    prop_collector, specSet=[filter_spec],
                                    options=options)

        perf_counter_infos = result.objects[0].propSet[0].val.PerfCounterInfo

        # Extract the counter Id for each counter and populate the map
        self._perf_counter_id_lookup_map = {}
        for perf_counter_info in perf_counter_infos:

            counter_group = perf_counter_info.groupInfo.key
            counter_name = perf_counter_info.nameInfo.key
            counter_rollup_type = perf_counter_info.rollupType
            counter_id = perf_counter_info.key

            counter_full_name = (counter_group + ":" + counter_name + ":" +
                                 counter_rollup_type)
            self._perf_counter_id_lookup_map[counter_full_name] = counter_id

    def query_host_stats(self, host_mor, counter_full_name):
        """Query host stats by counter full name"""
        if not self._perf_counter_id_lookup_map:
            self._init_perf_counter_id_lookup_map()
        counter_id = self._perf_counter_id_lookup_map[counter_full_name]

        session = self._session
        client_factory = session.vim.client.factory
        metric_id = client_factory.create('ns0:PerfMetricId')
        metric_id.counterId = counter_id
        metric_id.instance = ""
        query_spec = client_factory.create('ns0:PerfQuerySpec')
        query_spec.entity = host_mor
        query_spec.metricId = [metric_id]
        query_spec.intervalId = 20
        query_spec.maxSample = 1
        perf_manager = session.vim.service_content.perfManager
        perf_stats = session.invoke_api(session.vim, 'QueryPerf', perf_manager,
                                        querySpec=[query_spec])

        stat_value = 0
        if perf_stats:
            entity_metric = perf_stats[0]
            sample_infos = entity_metric.sampleInfo
            if len(sample_infos) > 0:
                for metric_series in entity_metric.value:
                    stat_value = float(sum(metric_series.value))

        return stat_value

    def get_host_cpu_stats(self):
        """Get host cpu stats and host state"""
        stats = {}
        # Get host cpu ut
        cpu_util = self.query_host_stats(self._host_mor, 'cpu:usage:average')
        stats["cpu.percent"] = cpu_util / 100

        summary = vm_util.get_host_summary(self._session, self._host_mor)
        if summary :
            # Get host cpu frequency
            cpuMhz = summary.hardware.cpuMhz
            numCpuCores = summary.hardware.numCpuCores
            stats["frequency"] = float(cpuMhz) * float(numCpuCores)
            # Get host state, include power state, connection state and maintenance
            state = {'powerState':'', 'connectionState':'', 'inMaintenanceMode':''}
            state['powerState'] = summary.runtime.powerState
            state['connectionState'] = summary.runtime.connectionState
            state['inMaintenanceMode'] = summary.runtime.inMaintenanceMode
            stats["hypervisor_state"] = state

        return stats

    def get_datacenter_info(self):
        """Get datacenter name of ESXi host to VMware monitor."""
        datacenters = self._session._call_method(vimUtil, "get_objects",
                                                 "Datacenter", ["name"])
        for dc in datacenters.objects:
            hostFolder = self._session._call_method(vimUtil,
                                                    'get_dynamic_property',
                                                    dc.obj, 'Datacenter',
                                                    'hostFolder')
            hosts = self._session._call_method(vimUtil,"get_contained_objects",
                                               hostFolder, "HostSystem")
            if (len(hosts) >0 and
                vm_util._get_object_for_value(hosts, self._host)):
                return dc.propSet[0].val
        return ""

    def set_host_service_enabled(self, enabled, disable_reason=None):
        """Enables / Disables the compute service on this host."""
        status_name = {True: 'disabled',
                       False: 'enabled'}

        disable_service = not enabled
        ctx = nova_context.get_admin_context()
        try:
            service = nova_objects.Service.get_by_compute_host(ctx, CONF.host)

            if service.disabled != disable_service:
                if not service.disabled or (
                        service.disabled_reason and
                        service.disabled_reason.startswith('AUTO: ')):
                    service.disabled = disable_service
                    service.disabled_reason = (
                       'AUTO: ' + disable_reason
                       if disable_service else 'None')
                    service.save()
                    LOG.debug('Updating compute service status to %s',
                              status_name[disable_service])
                else:
                    LOG.debug('Not overriding manual compute service '
                              'status with: %s',
                              status_name[disable_service])
        except exception.ComputeHostNotFound:
            LOG.warn(_LW('Cannot update service status on host: %s,'
                         'since it is not registered.'), CONF.host)
        except Exception:
            LOG.warn(_LW('Cannot update service status on host: %s,'
                         'due to an unexpected exception.'), CONF.host,
                     exc_info=True)
    # Vsettan-only (prs-related) end

    def live_migration(self, context, instance, dest,
                       post_method, recover_method, block_migration=False,
                       migrate_data=None):
        """Live migration of an instance to another host."""
        self._vmops.live_migration(context, instance, dest,
                                   post_method, recover_method,
                                   block_migration)

    def rollback_live_migration_at_destination(self, context, instance,
                                               network_info,
                                               block_device_info,
                                               destroy_disks=True,
                                               migrate_data=None):
        """Clean up destination node after a failed live migration."""
        self.destroy(context, instance, network_info, block_device_info)

    def get_instance_disk_info(self, instance, block_device_info=None):
        pass

    def get_vnc_console(self, context, instance):
        """Return link to instance's VNC console using vCenter logic."""
        # vCenter does not actually run the VNC service
        # itself. You must talk to the VNC host underneath vCenter.
        return self._vmops.get_vnc_console(instance)

    # Vsettan-only start
    def get_console_output(self, context, instance):
        return self._vmops.get_console_output(instance)
    # Vsettan-only end

    def _update_resources(self):
        #Vsettan Resource Pool BEGIN
        if self._res_pool_mor:
            self._nodename = self._res_pool_path
            self._volumeops = volumeops.VMwareVolumeOps(self._session,
                                                   self._cluster_mor,
                                                   self._host_mor,
                                                   resource_pool=self._res_pool_mor)
            self._vmops = vmops.VMwareVMOps(self._session, self._virtapi,
                                       self._volumeops,
                                       self._cluster_mor, self._host_mor,
                                       datastore_regex=self._datastore_regex,
                                       res_pool=self._res_pool_mor,
                                       storage_pod=self._storage_pod,
                                       nodename=self._nodename)
            self._vc_state = vcm_host.VCState(self._session, self._res_pool_path,
                                     self._cluster_mor, self._host_mor,
                                     resource_pool=self._res_pool_mor,
                                     datastore_regex=self._datastore_regex, #Vsettan-only
                                     storage_pod=self._storage_pod) #Vsettan-only
            LOG.info(_("Resource pool name is %s."), self._res_pool_name)
        #Vsettan Resource Pool END
        else:
            self._nodename = self._create_nodename(self._cluster_mor.value, 
                                             self._cluster_name)
            self._volumeops = volumeops.VMwareVolumeOps(self._session,
                                        self._cluster_mor)
            self._vmops = vmops.VMwareVMOps(self._session, self._virtapi,
                                       self._volumeops,
                                       self._cluster_mor,
                                       # Vsettan-only begin
                                       storage_pod=self._storage_pod,
                                       nodename=self._nodename,
                                       # Vsettan-only end
                                       datastore_regex=self._datastore_regex)
            self._vc_state = vcm_host.VCState(self._session, self._nodename,
                                     self._cluster_mor,
                                     datastore_regex=self._datastore_regex,
                                     storage_pod=self._storage_pod) #Vsettan-only
            LOG.info(_("Cluster_name is %s."), self._cluster_name)

        LOG.info(_("self.get_host_stats is %s."), self._vc_state.get_host_stats())
        '''raise exception.NotFound("All clusters specified %s were not"
                                           " found in the vCenter")'''

    def _get_vcenter_uuid(self):
        """Retrieves the vCenter UUID."""

        about = self._session._call_method(nova_vim_util, 'get_about_info')
        return about.instanceUuid


    def _create_nodename(self, mo_id, display_name):
        """Creates the name that is stored in hypervisor_hostname column.

        The name will be of the form similar to
        domain-1000(MyCluster)
        resgroup-1000(MyResourcePool)
        """
        return mo_id + '(' + display_name + ')'

    def _get_resource_for_node(self, nodename):
        """Gets the resource information for the specific node."""
        resource = self._resources.get(nodename)
        if not resource:
            msg = _("The resource %s does not exist") % nodename
            raise exception.NotFound(msg)
        return resource

    def _get_vmops_for_compute_node(self, nodename):
        """Retrieve vmops object from mo_id stored in the node name.

        Node name is of the form domain-1000(MyCluster)
        """
        resource = self._get_resource_for_node(nodename)
        return resource['vmops']

    def _get_volumeops_for_compute_node(self, nodename):
        """Retrieve vmops object from mo_id stored in the node name.

        Node name is of the form domain-1000(MyCluster)
        """
        resource = self._get_resource_for_node(nodename)
        return resource['volumeops']

    def _get_vc_state_for_compute_node(self, nodename):
        """Retrieve VCState object from mo_id stored in the node name.

        Node name is of the form domain-1000(MyCluster)
        """
        resource = self._get_resource_for_node(nodename)
        return resource['vcstate']

    def _get_available_resources(self, host_stats):
        return {'vcpus': host_stats['vcpus'],
               'memory_mb': host_stats['host_memory_total'],
               'local_gb': host_stats['disk_total'],
               'vcpus_used': 0,
               'memory_mb_used': host_stats['host_memory_total'] -
                                 host_stats['host_memory_free'],
               'local_gb_used': host_stats['disk_used'],
               'hypervisor_type': host_stats['hypervisor_type'],
               'hypervisor_version': host_stats['hypervisor_version'],
               'hypervisor_hostname': host_stats['hypervisor_hostname'],
                # The VMWare driver manages multiple hosts, so there are
                # likely many different CPU models in use. As such it is
                # impossible to provide any meaningful info on the CPU
                # model of the "host"
               'cpu_info': None,
               'supported_instances': host_stats['supported_instances'],
               'numa_topology': None,
               }

    def get_available_resource(self, nodename):
        """Retrieve resource info.

        This method is called when nova-compute launches, and
        as part of a periodic task.

        :returns: dictionary describing resources

        """
        host_stats = self._vc_state.get_host_stats(refresh=True)
        stats_dict = self._get_available_resources(host_stats)
        return stats_dict

    def get_available_nodes(self, refresh=False):
        """Returns nodenames of all nodes managed by the compute service.

        This driver supports only one compute node.
        """
        return [self._nodename]

    def spawn(self, context, instance, image_meta, injected_files,
              admin_password, network_info=None, block_device_info=None):
        """Create VM instance."""
        self._vmops.spawn(context, instance, image_meta, injected_files,
                          admin_password, network_info, block_device_info)

    def attach_volume(self, context, connection_info, instance, mountpoint,
                      disk_bus=None, device_type=None, encryption=None):
        """Attach volume storage to VM instance."""
        return self._volumeops.attach_volume(connection_info, instance)

    def detach_volume(self, connection_info, instance, mountpoint,
                      encryption=None):
        """Detach volume storage to VM instance."""
        return self._volumeops.detach_volume(connection_info, instance)

    def get_volume_connector(self, instance):
        """Return volume connector information."""
        return self._volumeops.get_volume_connector(instance)

    def get_host_ip_addr(self):
        """Returns the IP address of the vCenter host."""
        # Vsettan-only (prs-related) begin
        if CONF.vmware.esx_host_name:
            return CONF.vmware.esx_host_name
        # Vsettan-only (prs-related) end
        return CONF.vmware.host_ip

    def snapshot(self, context, instance, image_id, update_task_state):
        """Create snapshot from a running VM instance."""
        self._vmops.snapshot(context, instance, image_id, update_task_state)

    def reboot(self, context, instance, network_info, reboot_type,
               block_device_info=None, bad_volumes_callback=None):
        """Reboot VM instance."""
        self._vmops.reboot(instance, network_info, reboot_type)

    def _detach_instance_volumes(self, instance, block_device_info):
        # We need to detach attached volumes
        block_device_mapping = driver.block_device_info_get_mapping(
            block_device_info)
        if block_device_mapping:
            # Certain disk types, for example 'IDE' do not support hot
            # plugging. Hence we need to power off the instance and update
            # the instance state.
            self._vmops.power_off(instance)
            for disk in block_device_mapping:
                connection_info = disk['connection_info']
                try:
                    self.detach_volume(connection_info, instance,
                                       disk.get('device_name'))
                except exception.DiskNotFound:
                    LOG.warning(_LW('The volume %s does not exist!'),
                                disk.get('device_name'),
                                instance=instance)
                except Exception as e:
                    with excutils.save_and_reraise_exception():
                        LOG.error(_LE("Failed to detach %(device_name)s. "
                                      "Exception: %(exc)s"),
                                  {'device_name': disk.get('device_name'),
                                   'exc': e},
                                  instance=instance)

    def destroy(self, context, instance, network_info, block_device_info=None,
                destroy_disks=True, migrate_data=None):
        """Destroy VM instance."""

        # Destroy gets triggered when Resource Claim in resource_tracker
        # is not successful. When resource claim is not successful,
        # node is not set in instance. Perform destroy only if node is set
        if not instance.node:
            return

        # A resize uses the same instance on the VC. We do not delete that
        # VM in the event of a revert
        if instance.task_state == task_states.RESIZE_REVERTING:
            return

        # We need to detach attached volumes
        if block_device_info is not None:
            try:
                self._detach_instance_volumes(instance, block_device_info)
            except vexc.ManagedObjectNotFoundException:
                LOG.warning(_LW('Instance does not exists. Proceeding to '
                                'delete instance properties on datastore'),
                            instance=instance)
        self._vmops.destroy(instance, destroy_disks)

    def pause(self, instance):
        """Pause VM instance."""
        self._vmops.pause(instance)

    def unpause(self, instance):
        """Unpause paused VM instance."""
        self._vmops.unpause(instance)

    def suspend(self, context, instance):
        """Suspend the specified instance."""
        self._vmops.suspend(instance)

    def resume(self, context, instance, network_info, block_device_info=None):
        """Resume the suspended VM instance."""
        self._vmops.resume(instance)

    def rescue(self, context, instance, network_info, image_meta,
               rescue_password):
        """Rescue the specified instance."""
        self._vmops.rescue(context, instance, network_info, image_meta)

    def unrescue(self, instance, network_info):
        """Unrescue the specified instance."""
        self._vmops.unrescue(instance)

    def power_off(self, instance, timeout=0, retry_interval=0):
        """Power off the specified instance."""
        # TODO(PhilDay): Add support for timeout (clean shutdown)
        self._vmops.power_off(instance)

    def power_on(self, context, instance, network_info,
                 block_device_info=None):
        """Power on the specified instance."""
        self._vmops.power_on(instance)

    def poll_rebooting_instances(self, timeout, instances):
        """Poll for rebooting instances."""
        self._vmops.poll_rebooting_instances(timeout, instances)

    def get_info(self, instance):
        """Return info about the VM instance."""
        return self._vmops.get_info(instance)

    def get_all_power_state(self):
        """Return power state of all the VM instances."""
        return self._vmops.get_all_power_state()

    def get_diagnostics(self, instance):
        """Return data about VM diagnostics."""
        return self._vmops.get_diagnostics(instance)

    def get_instance_diagnostics(self, instance):
        """Return data about VM diagnostics."""
        return self._vmops.get_instance_diagnostics(instance)

    def host_power_action(self, action):
        """Host operations not supported by VC driver.

        This needs to override the ESX driver implementation.
        """
        raise NotImplementedError()

    def host_maintenance_mode(self, host, mode):
        """Host operations not supported by VC driver.

        This needs to override the ESX driver implementation.
        """
        raise NotImplementedError()

    def set_host_enabled(self, enabled):
        """Host operations not supported by VC driver.

        This needs to override the ESX driver implementation.
        """
        raise NotImplementedError()

    def get_host_uptime(self):
        """Host uptime operation not supported by VC driver."""

        msg = _("Multiple hosts may be managed by the VMWare "
                "vCenter driver; therefore we do not return "
                "uptime for just one host.")
        raise NotImplementedError(msg)

    def inject_network_info(self, instance, nw_info):
        """inject network info for specified instance."""
        self._vmops.inject_network_info(instance, nw_info)

    def manage_image_cache(self, context, all_instances):
        """Manage the local cache of images."""
        self._vmops.manage_image_cache(context, all_instances)

    def instance_exists(self, instance):
        """Efficient override of base instance_exists method."""
        return self._vmops.instance_exists(instance)

    def attach_interface(self, instance, image_meta, vif):
        """Attach an interface to the instance."""
        self._vmops.attach_interface(instance, image_meta, vif)

    def detach_interface(self, instance, vif):
        """Detach an interface from the instance."""
        self._vmops.detach_interface(instance, vif)

    # Vsettan-only start live snapshot
    def list_instance_snapshots(self, context, instance):
        """List snapshots of the instance."""
        _vmops = self._get_vmops_for_compute_node(instance.node)
        return _vmops.list_instance_snapshots(context, instance)

    def create_instance_snapshot(self, context, instance, snapshot_name,
                                 description, metadata):
        """Create snapshots of the instance."""
        _vmops = self._get_vmops_for_compute_node(instance.node)
        return _vmops.create_instance_snapshot(context,
            instance, snapshot_name=snapshot_name,
            description=description, metadata=metadata)

    def delete_instance_snapshot(self, context, instance, snapshot_id):
        """Delete snapshot of the instance."""
        _vmops = self._get_vmops_for_compute_node(instance.node)
        return _vmops.delete_instance_snapshot(context,
                                               instance,
                                               snapshot_id)

    def restore_instance_snapshot(self, context, instance, snapshot_id):
        """Restore snapshot of the instance."""
        _vmops = self._get_vmops_for_compute_node(instance.node)
        return _vmops.restore_instance_snapshot(context,
                                               instance,
                                               snapshot_id)
    # Vsettan-only stop live snapshot

    # Vsettan-only begin
    def retrieve_instances(self):

        """Retrieve cluster/resource pool VM instances."""
        node_list = self.get_available_nodes()
        cluster_instances = []
        for node in node_list:
            vmops = self._get_vmops_for_compute_node(node)
            cluster_instances += vmops.retrieve_instances()
        return cluster_instances

    def retrieve_instances(self, resource_pools, clusters):

        """Retrieve cluster/resource pool VM instances."""
        node = self.get_available_nodes()[0]
        vmops = self._get_vmops_for_compute_node(node)
        cluster_instances = vmops.retrieve_instances(resource_pools, clusters)
        return cluster_instances


    def associate_alternate_uuid_for_instance(self, instance):
        return self._vmops.associate_alternate_uuid_for_instance(instance)


    def get_disks_info(self, instance, volume_uuids):
        """Get disk device name, backing file path, size, and mountpoint"""
        return self._volumeops.get_disks_info(instance, volume_uuids)
    # Vsettan-only end

    # add api interface driver
    def get_datacenters(self, context, detail=False):
        """ Get datacenters for vCenter server. """
        datacenters = ds_util.get_datacenters(self._session, detail=detail)
        return datacenters

    def get_datastores(self, context, detail=False):
        """ Get datastores for vCenter cluster. """
        datastores = ds_util.get_datastores(self._session, detail=detail)
        return datastores

    def get_datastore_clusters(self, context, detail=False):
        """ Get datastore clusters for vCenter server. """
        ds_clusters = ds_util.get_datastore_clusters(self._session, detail=detail)
        return ds_clusters

    def get_esxi_hosts(self, context, detail=False):
        """ Get esxi hosts for vCenter cluster. """
        esxi_hosts = ds_util.get_esxi_hosts(self._session, detail=detail)
        return esxi_hosts

    def get_vnc_port_state(self, context, req_type):
        """ Get vnc available port for vCenter cluster. """
        vnc_port_state = vm_util.get_vnc_port_state(self._session, req_type)
        return vnc_port_state

    def get_virtual_adapter_network(self, context):
        """ Get datastores """
        networks = network_util.get_virtual_adapter_network(self._session)
        return networks

    def get_physical_adapter_network(self, context):
        """ Get datastores """
        networks = network_util.get_physical_adapter_network(self._session)
        return networks


class VMwareAPISession(api.VMwareAPISession):
    """Sets up a session with the VC/ESX host and handles all
    the calls made to the host.
    """
    def __init__(self, host_ip=CONF.vmware.host_ip,
                 host_port=CONF.vmware.host_port,
                 username=CONF.vmware.host_username,
                 password=CONF.vmware.host_password,
                 retry_count=CONF.vmware.api_retry_count,
                 scheme="https",
                 cacert=CONF.vmware.ca_file,
                 insecure=CONF.vmware.insecure):
        super(VMwareAPISession, self).__init__(
                host=host_ip,
                port=host_port,
                server_username=username,
                server_password=password,
                api_retry_count=retry_count,
                task_poll_interval=CONF.vmware.task_poll_interval,
                scheme=scheme,
                create_session=True,
                wsdl_loc=CONF.vmware.wsdl_location,
                cacert=cacert,
                insecure=insecure)

    def _is_vim_object(self, module):
        """Check if the module is a VIM Object instance."""
        return isinstance(module, vim.Vim)

    def _call_method(self, module, method, *args, **kwargs):
        """Calls a method within the module specified with
        args provided.
        """
        if not self._is_vim_object(module):
            return self.invoke_api(module, method, self.vim, *args, **kwargs)
        else:
            return self.invoke_api(module, method, *args, **kwargs)

    def _wait_for_task(self, task_ref):
        """Return a Deferred that will give the result of the given task.
        The task is polled until it completes.
        """
        return self.wait_for_task(task_ref)
