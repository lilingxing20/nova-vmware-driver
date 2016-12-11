#    Copyright 2016 Vsettan Corp.
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
Class for spawn VM from template.
"""

import collections
import os
import IPy as IP
import time

from oslo_config import cfg
from oslo_log import log as logging
from oslo_vmware import exceptions as vexc
from oslo_vmware.objects import datastore as ds_obj
from oslo_utils import excutils
from oslo_utils import units

from nova.api.metadata import base as instance_metadata
from nova.compute import power_state
from nova import context as nova_context
from nova import exception
from nova.i18n import _, _LE, _LI, _LW
from nova.objects import flavor as flavor_obj
from nova import utils
from nova.virt import configdrive
from nova.virt import driver
from nova.virt.vcmvmwareapi import constants
from nova.virt.vcmvmwareapi import ds_util
from nova.virt.vcmvmwareapi import vif as vmwarevif
from nova.virt.vcmvmwareapi import vim_util
from nova.virt.vcmvmwareapi import vm_util
from nova.virt.vcmvmwareapi import images
from nova.network.neutronv2 import api # Vsettan-only
###from nova.openstack.common import loopingcall # Vsettan-only
from oslo_service import loopingcall

ALL_SUPPORTED_NETWORK_DEVICES = ['VirtualE1000', 'VirtualE1000e',
                                 'VirtualPCNet32', 'VirtualSriovEthernetCard',
                                 'VirtualVmxnet', 'VirtualVmxnet3']

CONF = cfg.CONF
LOG = logging.getLogger(__name__)

DcInfo = collections.namedtuple('DcInfo',
                                ['ref', 'name', 'vmFolder'])

class TemplateNotFound(exception.NotFound):
    msg_fmt = _("Template %(template_name)s with %(template_instanceuuid)s "
                "not found for deployment.")

class VMwareVMTemplate(object):
    """Management class for VMTemplate-related tasks."""

    def __init__(self, session, virtapi, volumeops, cluster=None,
                 storage_pod=None, datastore_regex=None, res_pool=None):
        """Initializer."""
        self._session = session
        self._virtapi = virtapi
        self._volumeops = volumeops
        self._cluster = cluster
        self._storage_pod = storage_pod
        self._datastore_regex = datastore_regex
        self._is_neutron = utils.is_neutron()
        self._datastore_dc_mapping = {}
        self._res_pool=res_pool

    def _extend_virtual_disk(self, instance, requested_size, name, dc_ref):
        service_content = self._session.vim.service_content
        LOG.debug("Extending root virtual disk to %s", requested_size)
        vmdk_extend_task = self._session._call_method(
                self._session.vim,
                "ExtendVirtualDisk_Task",
                service_content.virtualDiskManager,
                name=name,
                datacenter=dc_ref,
                newCapacityKb=requested_size,
                eagerZero=False)
        try:
            self._session._wait_for_task(vmdk_extend_task)
        except Exception as e:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE('Extending virtual disk failed with error: %s'),
                          e, instance=instance)
                # Clean up files created during the extend operation
                files = [name.replace(".vmdk", "-flat.vmdk"), name]
                for file in files:
                    ds_path = ds_obj.DatastorePath.parse(file)
                    self._delete_datastore_file(ds_path, dc_ref)

        LOG.debug("Extended root virtual disk")

    def _delete_datastore_file(self, datastore_path, dc_ref):
        try:
            ds_util.file_delete(self._session, datastore_path, dc_ref)
        except (vexc.CannotDeleteFileException,
                vexc.FileFaultException,
                vexc.FileLockedException,
                vexc.FileNotFoundException):
            LOG.debug("Unable to delete %(ds)s. There may be more than "
                      "one process or thread trying to delete the file",
                      {'ds': datastore_path},
                      exc_info=True)

    def _get_vif_info_option(self, client_factory, iface_id, port_index):
        opt = client_factory.create('ns0:OptionValue')
        opt.key = "nvp.iface-id.%d" % port_index
        opt.value = iface_id
        return opt

    def get_first_network_device(self, hardware_devices):
        """Return the first network device."""
        if hardware_devices.__class__.__name__ == "ArrayOfVirtualDevice":
            hardware_devices = hardware_devices.VirtualDevice
        for device in hardware_devices:
            if device.__class__.__name__ in ALL_SUPPORTED_NETWORK_DEVICES:
                if hasattr(device, 'macAddress'):
                    return device

    def clone_vm_spec(self, client_factory, location,
                      power_on=False, snapshot=None,
                      template=False, config=None, customization=None):
        """Builds the VM clone spec."""
        clone_spec = client_factory.create('ns0:VirtualMachineCloneSpec')
        clone_spec.location = location
        clone_spec.powerOn = power_on
        if snapshot:
            clone_spec.snapshot = snapshot
        clone_spec.template = template
        if config:
            clone_spec.config = config
        if customization:
            clone_spec.customization = customization
        return clone_spec

    def relocate_vm_spec(self, client_factory, datastore=None, host=None,
                         disk_move_type="moveAllDiskBackingsAndDisallowSharing",
                         pool=None):
        """Builds the VM relocation spec."""
        rel_spec = client_factory.create('ns0:VirtualMachineRelocateSpec')
        rel_spec.datastore = datastore
        rel_spec.diskMoveType = disk_move_type
        if host:
            rel_spec.host = host
        if pool:
            rel_spec.pool = pool
        return rel_spec


    def get_storage_drs_pod_selection_spec(self, client_factory, storage_pod):
        """Builds the Storage DRS Pod Selection spec."""
        pod_spec = client_factory.create('ns0:StorageDrsPodSelectionSpec')
        pod_spec.storagePod = storage_pod
        return pod_spec

    def get_storage_placement_spec(self, client_factory, type,
                                   pod_selection_spec, config_spec=None,
                                   clone_spec=None, clone_name=None,
                                   folder=None, vm=None):
        """Builds the Storage Placement spec."""
        storage_spec = client_factory.create('ns0:StoragePlacementSpec')
        storage_spec.type = type
        storage_spec.podSelectionSpec = pod_selection_spec
        storage_spec.cloneName = clone_name
        storage_spec.cloneSpec = clone_spec
        storage_spec.configSpec = config_spec
        storage_spec.folder = folder
        storage_spec.vm = vm
        return storage_spec

    def _get_vmfolder_ref(self):
        """Get the Vm folder ref from the datacenter."""
        dc_objs = self._session._call_method(vim_util, "get_objects",
                                             "Datacenter", ["vmFolder"])
        vm_util._cancel_retrieve_if_necessary(self._session, dc_objs)
        # There is only one default datacenter in a standalone ESX host
        vm_folder_ref = dc_objs.objects[0].propSet[0].val
        return vm_folder_ref

    def _clonevm(self, instance, client_factory, data_store_ref,
                 res_pool_ref, template_ref, config_spec, custspec):
        """Clone the VM on ESX host."""
        dc_info = self.get_datacenter_ref_and_name(data_store_ref)
        vm_folder_ref = dc_info.vmFolder
        rel_spec = self.relocate_vm_spec(client_factory,
                                            data_store_ref,
                                            pool=res_pool_ref)

        if config_spec:
            hardware_devices = self._session._call_method(vim_util,
                            "get_dynamic_property", template_ref,
                            "VirtualMachine", "config.hardware.device")
            device = self.get_first_network_device(hardware_devices)
            if device:
                # To avoid the nic of clone vm has the same mac address with
                # the template.
                # first, delete the nic device which cloned from template,
                # secondly, add one nic device and assign the correct
                # mac address in it.
                LOG.debug(_("Reconfiguring VM to detach interface"),
                          instance=instance)
                detach_config_spec = vm_util.get_network_detach_config_spec(
                                             client_factory, device, 0)
                config_spec.deviceChange.append(
                            detach_config_spec.deviceChange)

        clone_spec = self.clone_vm_spec(client_factory,
                                        location=rel_spec,
                                        config=config_spec,
                                        customization=custspec)

        if self._storage_pod is None:
            use_sdrs = False
        else:
            # Read 'use_sdrs' from flavor and override configuration value
            flavor = instance.flavor
            flavor_use_sdrs = flavor.get('extra_specs').get('vmware:use_sdrs',
                                                     None)
            if flavor_use_sdrs == 'True':
                use_sdrs = True
            elif flavor_use_sdrs == 'False':
                use_sdrs = False
            else:
                use_sdrs = CONF.vmware.use_sdrs

        # If DRS is enabled on datastore cluster, will attempt to call DRS
        if use_sdrs and self._storage_pod:
            drs_enabled = self._session._call_method(vim_util,
                "get_dynamic_property", self._storage_pod,
                "StoragePod",
                "podStorageDrsEntry.storageDrsConfig.podConfig.enabled")
            if drs_enabled:
                use_sdrs = True
            else:
                use_sdrs = False
                LOG.warn(_("Storage DRS is not enabled on StoragePod %s")
                         % CONF.vmware.datastore_cluster_name)

        if use_sdrs and self._storage_pod:
            pod_spec = self.get_storage_drs_pod_selection_spec(
                                client_factory, self._storage_pod)
            storage_spec = self.get_storage_placement_spec(
                                client_factory, type='clone',
                                pod_selection_spec=pod_spec,
                                clone_name=instance.uuid,
                                clone_spec=clone_spec,
                                folder=vm_folder_ref,
                                vm=template_ref)

            service_content = self._session.vim.service_content
            storage_mgr = service_content.storageResourceManager

            result = self._session._call_method(self._session.vim,
                                                "RecommendDatastores",
                                                storage_mgr,
                                                storageSpec=storage_spec)

            if hasattr(result, 'task') and result.task is not None:
                LOG.info(_("DRS is automated, wait for clone task to complete"))
                self._session._wait_for_task(result.task)
            elif (hasattr(result, 'recommendations') and
                  len(result.recommendations) > 0):
                LOG.info(_("DRS is not automated, manually apply clone task"))
                best = result.recommendations[0]
                if hasattr(best, 'rating'):
                    for recommend in enumerate(result.recommendations):
                        if (hasattr(recommend, 'rating') and
                            recommend.rating > best.rating):
                            best = recommend
                keys = []
                if hasattr(best, 'prerequisite'):
                    keys.append(best.prerequisite)
                keys.append(best.key)
                task = self._session._call_method(
                                           self._session.vim,
                                           "ApplyStorageDrsRecommendation_Task",
                                           storage_mgr,
                                           key=keys)
                self._session._wait_for_task(task)
            else:
                LOG.info(_("No DRS recommendation. Need to apply CloneVM_Task()."))
                use_sdrs = False

        if not use_sdrs:
            vm_clone_task = self._session._call_method(
                                self._session.vim,
                                "CloneVM_Task", template_ref,
                                folder=vm_folder_ref,
                                name=config_spec.name,
                                spec=clone_spec)

            self._session._wait_for_task(vm_clone_task)

    def _power_on_vm(self, instance, vm_ref):
        """Power on the VM."""
        LOG.debug(_("Powering on the VM instance"), instance=instance)
        # Power On the VM
        power_on_task = self._session._call_method(
                           self._session.vim,
                           "PowerOnVM_Task", vm_ref)
        self._session._wait_for_task(power_on_task)
        LOG.debug(_("Powered on the VM instance"), instance=instance)

    def _update_datacenter_cache_from_objects(self, dcs):
        """Updates the datastore/datacenter cache."""

        while dcs:
            token = vm_util._get_token(dcs)
            for dco in dcs.objects:
                dc_ref = dco.obj
                ds_refs = []
                prop_dict = vm_util.propset_dict(dco.propSet)
                name = prop_dict.get('name')
                vmFolder = prop_dict.get('vmFolder')
                datastore_refs = prop_dict.get('datastore')
                if datastore_refs:
                    datastore_refs = datastore_refs.ManagedObjectReference
                    for ds in datastore_refs:
                        ds_refs.append(ds.value)
                else:
                    LOG.debug("Datacenter %s doesn't have any datastore "
                              "associated with it, ignoring it", name)
                for ds_ref in ds_refs:
                    self._datastore_dc_mapping[ds_ref] = DcInfo(ref=dc_ref,
                            name=name, vmFolder=vmFolder)

            if token:
                dcs = self._session._call_method(vim_util,
                                                 "continue_to_get_objects",
                                                 token)
            else:
                break

    def get_datacenter_ref_and_name(self, ds_ref):
        """Get the datacenter name and the reference."""
        dc_info = self._datastore_dc_mapping.get(ds_ref.value)
        if not dc_info:
            dcs = self._session._call_method(vim_util, "get_objects",
                    "Datacenter", ["name", "datastore", "vmFolder"])
            self._update_datacenter_cache_from_objects(dcs)
            dc_info = self._datastore_dc_mapping.get(ds_ref.value)
        return dc_info

    def _get_image_properties(self, context, instance):
        """Get the template image properties.
        """
        image_ref = instance.get('image_ref')
        if image_ref:
            _image_info = images.get_vmdk_size_and_properties(
                    context, image_ref, instance)
        image_size, image_properties = _image_info
        LOG.debug(_("image_size: %(image_size)s and image_properties: %(image_properties)s"),
                   {'image_size': image_size, 'image_properties': image_properties})
        vmdk_file_size_in_kb = int(image_size) / 1024
        # Get the network card type from the image properties.
        vif_model = image_properties.get("hw_vif_model",
                                         "VirtualE1000")
        # Get the template name
        template_name = image_properties.get("template_name")
        # Get image instanceuuid
        template_instanceuuid = image_properties.get("template_instanceuuid")
        # Get root disk size for the image
        root_disk_size = image_properties.get("root_disk_size", None)
        if root_disk_size:
            vmdk_file_size_in_kb = int(root_disk_size) / 1024
        adapter_type = image_properties.get('vmware_adaptertype', 'ide')
        return (vmdk_file_size_in_kb, vif_model, template_name, template_instanceuuid, adapter_type)

    def execute_clone_vm(self, session, instance, instance_name, vif_infos, network_info, data_store_name,
                          data_store_ref, res_pool_ref, template_ref, instanceUuid=None):
        client_factory = self._session.vim.client.factory
        flavor = instance.flavor
        extra_specs = self._get_extra_specs(flavor)
        if extra_specs.storage_policy:
            profile_spec = vm_util.get_storage_profile_spec(
                self._session, extra_specs.storage_policy)
        else:
            profile_spec = None

        guest_id = vm_util.get_dynamic_property_mor(self._session,
                                                    template_ref,
                                                    'config.guestId')
        config_spec = vm_util.get_vm_create_spec(
                          client_factory, instance,
                          instance_name, data_store_name, vif_infos,
                          extra_specs,
                          os_type=guest_id,
                          instanceUuid=instanceUuid,
                          profile_spec=profile_spec,
                          metadata=None,
                          ds_ref=data_store_ref)

        custspec = None
        tools_version = vm_util.get_dynamic_property_mor(self._session,
                                                         template_ref,
                                                         'config.tools.toolsVersion')

        if (network_info and 'dhcp_server' not in network_info[0]['network']['subnets'][0]['meta']
               and tools_version > 0
               and CONF.vmware.customization_enabled):
            custspec = vm_util.get_vm_cust_spec(client_factory, instance, network_info, guest_id)

        try:
            self._clonevm(instance, client_factory, data_store_ref,
                          res_pool_ref, template_ref, config_spec, custspec)
            return custspec
        except Exception as e:
            with excutils.save_and_reraise_exception():
                LOG.error(_('Clone VM failed! Error: %s'),
                          e, instance=instance)

    def _get_extra_specs(self, flavor):
        extra_specs = vm_util.ExtraSpecs()
        for (key, type) in (('cpu_limit', int),
                            ('cpu_reservation', int),
                            ('cpu_shares_level', str),
                            ('cpu_shares_share', int)):
            value = flavor.get('extra_specs').get('quota:' + key) #Vsettan-only
            if value:
                setattr(extra_specs.cpu_limits, key, type(value))
        hw_version = flavor.get('extra_specs').get('vmware:hw_version') #Vsettan-only
        extra_specs.hw_version = hw_version
        if CONF.vmware.pbm_enabled:
            storage_policy = flavor.get('extra_specs').get('vmware:storage_policy', #Vsettan-only
                    CONF.vmware.pbm_default_policy)
            extra_specs.storage_policy = storage_policy
        return extra_specs

    # Vsettan-only start
    # Update port with the ip address assigned by external dhcp
    def update_ip(self, context, vm_ref, ins_port_id, ins_fake_ip, ins_subnet_id, i, nic_num):
        sleep_time = CONF.vmware.time_wait_for_ip_matching
        time.sleep(sleep_time)
        lst_properties = ["guest.net", "config.guestId"]
        props = self._session._call_method(vim_util, "get_object_properties",
                                           None, vm_ref, "VirtualMachine",
                                           lst_properties)
        query = vm_util.get_values_from_object_properties(self._session, props)
        if query["guest.net"] == '':
            return
        if 'win' in query["config.guestId"]:
            vm_guest_ip_set = query["guest.net"][0][nic_num-1-i]['ipAddress']
        else:
            vm_guest_ip_set = query["guest.net"][0][i]['ipAddress']
        for j in range(len(vm_guest_ip_set)):
            parse_ip = IP.parseAddress(vm_guest_ip_set[j])
            if parse_ip[1] == 4:
                vm_guest_ip = vm_guest_ip_set[j]
        LOG.info('Guest ip address is %s', vm_guest_ip)
        if ins_fake_ip != vm_guest_ip:
            LOG.info('Start to update port information with exact guest ip address')
            updated_fixed_ips = [{'subnet_id': ins_subnet_id, 'ip_address': vm_guest_ip}]
            port_req_body = {'port': {'fixed_ips': updated_fixed_ips}}
            try:
                api.get_client(context).update_port(ins_port_id, port_req_body)
            except Exception as ex:
                msg = ("Unable to update port %(portid)s on subnet "
                       "%(subnet_id)s with failure: %(exception)s")
                LOG.debug(msg, {'portid': ins_port_id,
                                'subnet_id': ins_subnet_id,
                                'exception': ex})

    # Loop to get the guest ip address
    def _wait_for_assigned_ip(self, context, vm_ref, timeout_count, ins_port_id,
                              ins_fake_ip, ins_subnet_id, i, nic_num):
        lst_properties = ["guest.net", "summary.guest.toolsRunningStatus"]
        props = self._session._call_method(vim_util, "get_object_properties",
                                           None, vm_ref, "VirtualMachine",
                                           lst_properties)
        query = vm_util.get_values_from_object_properties(self._session, props)
        timeout_count.pop()
        if (query['summary.guest.toolsRunningStatus'] == 'guestToolsRunning'
            and query['guest.net'] != ''):
            self.update_ip(context, vm_ref, ins_port_id, ins_fake_ip, ins_subnet_id, i, nic_num)
            raise loopingcall.LoopingCallDone()
        if len(timeout_count) == 0:
            LOG.error('Timeout for getting ip address via vmware tools against fake ip: %s', ins_fake_ip)
            raise loopingcall.LoopingCallDone()
    # Vsettan-only end

    def spawn_from_template(self, context, instance, image_meta,
              injected_files, admin_password, network_info,
              block_device_info=None, instance_name=None, power_on=True):

        """Creates a VM instance from template by calling CloneVM_Task.
        """
        root_gb = instance.root_gb
        root_gb_in_kb = root_gb * units.Mi

        (vmdk_file_size_in_kb, vif_model, template_name, template_instanceuuid, adapter_type) = self.\
        _get_image_properties(context, instance)

        ds = ds_util.get_datastore(self._session, self._cluster,
                 storage_pod=self._storage_pod,
                 datastore_regex=self._datastore_regex,
                 limit_size=root_gb * units.Gi)
        data_store_ref = ds.ref
        data_store_name = ds.name
        dc_info = self.get_datacenter_ref_and_name(data_store_ref)

        template_ref = None
        if not template_instanceuuid:
            template_ref = vm_util.get_vm_ref_from_name(self._session,
                                                    template_name)
        else: # if instanceuuid is not None, use it to retrieve vmref
            template_ref = vm_util.get_template_ref_from_uuid(self._session,
                                                    template_instanceuuid)
        if template_ref is None:
            LOG.error(_('Template %(template_name)s: %(template_instanceuuid)s not found!'),
                     {'template_name': template_name, 'template_instanceuuid': template_instanceuuid},
                     instance=instance)
            raise TemplateNotFound(template_instanceuuid = template_instanceuuid,
                                   template_name = template_name)

        if not vmdk_file_size_in_kb:
            template_size_in_byte_committed = vm_util.get_dynamic_property_mor(self._session,
                                                                   template_ref,
                                                                   'summary.storage.committed')
            template_size_in_byte_uncommitted = vm_util.get_dynamic_property_mor(self._session,
                                                                   template_ref,
                                                                   'summary.storage.uncommitted')
            template_size_in_byte_committed = int(template_size_in_byte_committed)
            template_size_in_byte_uncommitted = int(template_size_in_byte_uncommitted)
            vmdk_file_size_in_byte = template_size_in_byte_committed + template_size_in_byte_uncommitted
            vmdk_file_size_in_kb = vmdk_file_size_in_byte / 1024
            LOG.info(_("Template %(template_name)s declares disk size "
                       "%(total)s KB in total, including "
                       "%(committed)s KB committed, and "
                       "%(uncommitted)s KB uncommitted"),
                     {"template_name":template_name, "total":vmdk_file_size_in_kb,
                      "committed":template_size_in_byte_committed / 1024,
                      "uncommitted":template_size_in_byte_uncommitted / 1024},
                     instance=instance)

        if root_gb_in_kb and vmdk_file_size_in_kb > root_gb_in_kb:
            reason = _("Flavor's disk size %s KB is too small for the requested "
                       "template's disk size %s KB, please use larger flavor." %
                       (root_gb_in_kb, vmdk_file_size_in_kb))
            raise exception.InstanceUnacceptable(instance_id=instance.uuid,
                                                 reason=reason)

        if self._res_pool:
            res_pool_ref = self._res_pool
        else:
            res_pool_ref = vm_util.get_res_pool_ref(self._session,
                                                    self._cluster)

        ## Check instance memory whether exceed resource pool allowed
        memory_limit = vm_util.get_dynamic_property_mor(self._session, res_pool_ref, \
                                          'config.memoryAllocation.limit')
        ## Patch for set unlimited memory from vcenter side
        if memory_limit > 0 and instance.memory_mb > memory_limit:
            reason = _("Instance memory size %s MB larger than "
                       "resource pool limit %s MB, please use proper flavor for deployment." %
                       (instance.memory_mb, memory_limit))
            raise exception.InstanceUnacceptable(instance_id=instance.uuid,
                                                 reason=reason)

        vif_infos = vmwarevif.get_vif_info(self._session, self._cluster, None,
                                           utils.is_neutron(), vif_model,
                                           network_info)

        # Get the instance name. In some cases this may differ from the 'uuid',
        # for example when the spawn of a rescue instance takes place.
        if not instance_name:
            instance_name = vm_util.get_vm_name_for_vcenter(instance)

        customization_spec = self.execute_clone_vm(self._session, instance, instance_name, vif_infos,
                                                   network_info, data_store_name, data_store_ref,
                                                   res_pool_ref, template_ref, instance.uuid)

        if instance_name != instance.uuid:
            vm_ref = vm_util.get_vm_ref_from_name(self._session,
                                                  instance_name)
        else:
            vm_ref = vm_util.get_vm_ref(self._session, instance)

        vmdk_info = vm_util.get_vmdk_info(self._session, vm_ref,
                                          instance.uuid)
        vmdk_path = vmdk_info.path
        # extend virtual disk to flavor disk size if template disk size is larger than root_gb
        if root_gb_in_kb > 0 and root_gb_in_kb > vmdk_file_size_in_kb:
            self._extend_virtual_disk(instance, root_gb_in_kb, vmdk_path,
                                      dc_info.ref)

        cookies = self._session.vim.client.options.transport.cookiejar

        # Create ephemeral disks
        self._create_ephemeral(block_device_info, instance, vm_ref,
                               dc_info, ds, instance_name, adapter_type)

        if configdrive.required_by(instance):
            uploaded_iso_path = self._create_config_drive(instance,
                                                          injected_files,
                                                          admin_password,
                                                          data_store_name,
                                                          dc_info.name,
                                                          instance.uuid,
                                                          cookies)
            uploaded_iso_path = ds_util.build_datastore_path(
                data_store_name,
                uploaded_iso_path)
            self._attach_cdrom_to_vm(
                vm_ref, instance,
                data_store_ref,
                uploaded_iso_path)

        # Vsettan-only start
        # Add support for attaching non-root disk volumes during instance boot
        if instance.image_ref and block_device_info:
            LOG.debug(_("Block device information present for template path: %s")
                      % block_device_info, instance=instance)
            block_device_mapping = driver.block_device_info_get_mapping(
                block_device_info)
            if block_device_mapping is not None:
                for disk in block_device_mapping:
                    connection_info = disk['connection_info']
                    # attach_root_volume could also apply to non-root disk relocate/attach
                    self._volumeops.attach_root_volume(connection_info, instance,
                                                       disk['mount_device'],
                                                       data_store_ref)
        # Vsettan-only end
        if power_on:
            self._power_on_vm(instance, vm_ref)
        # Vsettan-only start
        tools_version = vm_util.get_dynamic_property_mor(self._session,
                                                         template_ref,
                                                         'config.tools.toolsVersion')
        if tools_version > 0:
            lst_properties = ["runtime.powerState"]
            props = self._session._call_method(vim_util, "get_object_properties",
                                               None, vm_ref, "VirtualMachine",
                                               lst_properties)
            query = vm_util.get_values_from_object_properties(self._session, props)
            if query['runtime.powerState'] == "poweredOn":
                nic_num = len(network_info)
                for i in range(nic_num):
                     # Once external dhcp function is enabled
                     # Get the information via vmware tool
                    if 'dhcp_server' not in network_info[i]['network']['subnets'][0]['meta']:
                        ins_network_id = network_info[i]['network']['id']
                        ins_fake_ip = network_info[i]['network']['subnets'][0]['ips'][0]['address']
                        ins_port_id = network_info[i]['id']
                        search_opts = {'id': ins_port_id}
                        port_data = api.get_client(context).list_ports(**search_opts)
                        ins_subnet_id = port_data['ports'][0]['fixed_ips'][0]['subnet_id']

                        if customization_spec and customization_spec.nicSettingMap:
                            expected_ip = customization_spec.nicSettingMap[i].adapter.ip.ipAddress
                            if expected_ip != ins_fake_ip:
                                LOG.info('After VM customization, update neutron port %s with customized ip address %s',
                                         ins_port_id, expected_ip)
                                updated_fixed_ips = [{'subnet_id': ins_subnet_id, 'ip_address': expected_ip}]
                                port_req_body = {'port': {'fixed_ips': updated_fixed_ips}}
                                try:
                                    api.get_client(context).update_port(ins_port_id, port_req_body)
                                except Exception as ex:
                                    msg = ("Unable to update port %(portid)s on subnet "
                                          "%(subnet_id)s with failure: %(exception)s")
                                    LOG.debug(msg, {'portid': ins_port_id,
                                             'subnet_id': ins_subnet_id,
                                             'exception': ex})
                            continue

                        timeout_count = range(CONF.vmware.external_dhcp_retry_count)
                        timer = loopingcall.FixedIntervalLoopingCall(self._wait_for_assigned_ip,
                                                                     context, vm_ref, timeout_count,
                                                                     ins_port_id, ins_fake_ip,
                                                                     ins_subnet_id, i, nic_num)
                        timer.start(interval=CONF.vmware.external_dhcp_interval).wait()
        # Vsettan-only end
        return vm_ref


    def _create_config_drive(self, instance, injected_files, admin_password,
                             data_store_name, dc_name, upload_folder, cookies):
        if CONF.config_drive_format != 'iso9660':
            reason = (_('Invalid config_drive_format "%s"') %
                      CONF.config_drive_format)
            raise exception.InstancePowerOnFailure(reason=reason)

        LOG.info(_('Using config drive for instance'), instance=instance)
        extra_md = {}
        if admin_password:
            extra_md['admin_pass'] = admin_password

        inst_md = instance_metadata.InstanceMetadata(instance,
                                                     content=injected_files,
                                                     extra_md=extra_md)
        try:
            with configdrive.ConfigDriveBuilder(instance_md=inst_md) as cdb:
                with utils.tempdir() as tmp_path:
                    tmp_file = os.path.join(tmp_path, 'configdrive.iso')
                    cdb.make_drive(tmp_file)
                    upload_iso_path = "%s/configdrive.iso" % (
                        upload_folder)
                    images.upload_iso_to_datastore(
                        tmp_file, instance,
                        host=self._session._host,
                        port=self._session._port,
                        data_center_name=dc_name,
                        datastore_name=data_store_name,
                        cookies=cookies,
                        file_path=upload_iso_path)
                    return upload_iso_path
        except Exception as e:
            with excutils.save_and_reraise_exception():
                LOG.error(_('Creating config drive failed with error: %s'),
                          e, instance=instance)

    def _attach_cdrom_to_vm(self, vm_ref, instance,
                            datastore, file_path):
        """Attach cdrom to VM by reconfiguration."""
        client_factory = self._session.vim.client.factory
        devices = self._session._call_method(vim_util,
                                    "get_dynamic_property", vm_ref,
                                    "VirtualMachine", "config.hardware.device")
        (controller_key, unit_number,
         controller_spec) = vm_util.allocate_controller_key_and_unit_number(
                                                              client_factory,
                                                              devices,
                                                              'ide')
        cdrom_attach_config_spec = vm_util.get_cdrom_attach_config_spec(
                                    client_factory, datastore, file_path,
                                    controller_key, unit_number)
        if controller_spec:
            cdrom_attach_config_spec.deviceChange.append(controller_spec)

        LOG.debug("Reconfiguring VM instance to attach cdrom %s",
                  file_path, instance=instance)
        vm_util.reconfigure_vm(self._session, vm_ref, cdrom_attach_config_spec)
        LOG.debug("Reconfigured VM instance to attach cdrom %s",
                  file_path, instance=instance)

    def _create_and_attach_ephemeral_disk(self, instance, vm_ref, dc_info,
                                          size, adapter_type, path):
        disk_type = constants.DISK_TYPE_THIN
        vm_util.create_virtual_disk(
                self._session, dc_info.ref,
                adapter_type,
                disk_type,
                path,
                size)

        self._volumeops.attach_disk_to_vm(
                vm_ref, instance,
                adapter_type, disk_type,
                path, size, False)

    def _create_ephemeral(self, bdi, instance, vm_ref, dc_info,
                          datastore, folder, adapter_type):
        ephemerals = None
        if bdi is not None:
            ephemerals = driver.block_device_info_get_ephemerals(bdi)
            for idx, eph in enumerate(ephemerals):
                size = eph['size'] * units.Mi
                at = eph.get('disk_bus', adapter_type)
                filename = vm_util.get_ephemeral_name(idx)
                path = str(ds_obj.DatastorePath(datastore.name, folder,
                                                filename))
                self._create_and_attach_ephemeral_disk(instance, vm_ref,
                                                       dc_info, size,
                                                       at, path)
        # There may be block devices defined but no ephemerals. In this case
        # we need to allocate a ephemeral disk if required
        if not ephemerals and instance.ephemeral_gb:
            size = instance.ephemeral_gb * units.Mi
            filename = vm_util.get_ephemeral_name(0)
            path = str(ds_obj.DatastorePath(datastore.name, folder,
                                            filename))
            self._create_and_attach_ephemeral_disk(instance, vm_ref,
                                                   dc_info, size,
                                                   adapter_type, path)
