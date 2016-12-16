# Copyright 2016 Vsettan Corp.
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
Class for VM tasks like spawn, snapshot, suspend, resume etc.
"""

import collections
import os
import time
import tempfile # Vsettan-only
import urllib2 # Vsettan-only
import urlparse # Vsettan-only

import decorator
from oslo_concurrency import lockutils
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import excutils
from oslo_utils import strutils
from oslo_utils import units
from oslo_utils import uuidutils
from oslo_vmware import exceptions as vexc
from oslo_vmware.objects import datastore as ds_obj
from oslo_vmware import vim_util as vutil

from nova.api.metadata import base as instance_metadata
from nova import compute
from nova.compute import power_state
from nova.compute import task_states
from nova.compute import vm_states
from nova.console import type as ctype
from nova import context as nova_context
from nova import exception
from nova.i18n import _, _LE, _LI, _LW
from nova import network
from nova import objects
from nova import utils
from nova import version
from nova.virt import configdrive
from nova.virt import diagnostics
from nova.virt import driver
from nova.virt import hardware
from nova.virt.vcmvmwareapi import constants
from nova.virt.vcmvmwareapi import ds_util
from nova.virt.vcmvmwareapi import error_util
from nova.virt.vcmvmwareapi import imagecache
from nova.virt.vcmvmwareapi import images
from nova.virt.vcmvmwareapi import vif as vmwarevif
from nova.virt.vcmvmwareapi import vim_util
from nova.virt.vcmvmwareapi import vm_util
from nova.virt.vcmvmwareapi import read_write_util # Vsettan-only
from nova.virt.vcmvmwareapi import template # Vsettan-only
from nova.image import glance # Vsettan-only
# Vsettan-ONLY START snapshot to template
from nova.compute import utils as compute_utils
from nova import image
# Vsettan-ONLY STOP

vmops_opts = [
    cfg.StrOpt('cache_prefix',
               help='The prefix for where cached images are stored. This is '
                    'NOT the full path - just a folder prefix. '
                    'This should only be used when a datastore cache should '
                    'be shared between compute nodes. Note: this should only '
                    'be used when the compute nodes have a shared file '
                    'system.'),
    ]

CONF = cfg.CONF
CONF.register_opts(vmops_opts, 'vmware')

CONF.import_opt('image_cache_subdirectory_name', 'nova.virt.imagecache')
CONF.import_opt('remove_unused_base_images', 'nova.virt.imagecache')
###CONF.import_opt('vnc_enabled', 'nova.vnc')
CONF.import_opt('enabled', 'nova.vnc', 'vnc')
CONF.vnc_enabled=CONF.vnc.enabled

CONF.import_opt('my_ip', 'nova.netconf')

IMAGE_SERVICE = glance.GlanceImageService() # Vsettan-only
DS_URL_PREFIX = '/folder' # Vsettan-only

LOG = logging.getLogger(__name__)

VMWARE_POWER_STATES = {'poweredOff': power_state.SHUTDOWN,
                       'poweredOn': power_state.RUNNING,
                       'suspended': power_state.SUSPENDED}

# Vsettan-only begin
VMWARE_VM_STATES = {'poweredOff': vm_states.STOPPED,
                    'poweredOn': vm_states.ACTIVE,
                    'suspended': vm_states.SUSPENDED}

MAX_CONSOLE_BYTES = 100 * units.Ki
# Vsettan-only end

RESIZE_TOTAL_STEPS = 6

DcInfo = collections.namedtuple('DcInfo',
                                ['ref', 'name', 'vmFolder'])


class VirtualMachineInstanceConfigInfo(object):
    """Parameters needed to create and configure a new instance."""

    def __init__(self, instance, instance_name, image_info, datastore, dc_info,
                 image_cache, extra_specs=None):

        # Some methods called during spawn take the instance parameter purely
        # for logging purposes.
        # TODO(vui) Clean them up, so we no longer need to keep this variable
        self.instance = instance

        # Get the instance name. In some cases this may differ from the 'uuid',
        # for example when the spawn of a rescue instance takes place.
        self.instance_name = instance_name or instance.uuid

        self.ii = image_info
        self.root_gb = instance.root_gb
        self.datastore = datastore
        self.dc_info = dc_info
        self._image_cache = image_cache
        self._extra_specs = extra_specs

    @property
    def cache_image_folder(self):
        if self.ii.image_id is None:
            return
        return self._image_cache.get_image_cache_folder(
                   self.datastore, self.ii.image_id)

    @property
    def cache_image_path(self):
        if self.ii.image_id is None:
            return
        cached_image_file_name = "%s.%s" % (self.ii.image_id,
                                            self.ii.file_type)
        return self.cache_image_folder.join(cached_image_file_name)


# Note(vui): See https://bugs.launchpad.net/nova/+bug/1363349
# for cases where mocking time.sleep() can have unintended effects on code
# not under test. For now, unblock the affected test cases by providing
# a wrapper function to work around needing to mock time.sleep()
def _time_sleep_wrapper(delay):
    time.sleep(delay)


@decorator.decorator
def retry_if_task_in_progress(f, *args, **kwargs):
    retries = max(CONF.vmware.api_retry_count, 1)
    delay = 1
    for attempt in range(1, retries + 1):
        if attempt != 1:
            _time_sleep_wrapper(delay)
            delay = min(2 * delay, 60)
        try:
            f(*args, **kwargs)
            return
        except vexc.TaskInProgress:
            pass


class VMwareVMOps(object):
    """Management class for VM-related tasks."""

    def __init__(self, session, virtapi, volumeops, cluster=None,
                 # Vsettan-only begin
                 host=None,
                 storage_pod=None,
                 use_sdrs=False,
                 nodename=None,
                 # Vsettan-only end
                 datastore_regex=None,
                 # Vsettan Resource Pool BEGIN
                 res_pool=None
                 # Vsettan Resource Pool END
                 ):
        """Initializer."""
        self.compute_api = compute.API()
        # Vsettan-ONLY START snapshot to template
        self.image_api = image.API()
        # Vsettan-ONLY STOP
        self._session = session
        self._virtapi = virtapi
        self._volumeops = volumeops
        self._cluster = cluster
        self._host = host #Vsettan-only
        self._root_resource_pool = vm_util.get_res_pool_ref(self._session,
                                                            self._cluster)
        self._datastore_regex = datastore_regex
        # Vsettan-only begin
        self._storage_pod = storage_pod
        self._nodename = nodename
        # Vsettan-only end
        # Vsettan Resource Pool BEGIN
        self._res_pool = res_pool
        # Vsettan Resource Pool END

        self._base_folder = self._get_base_folder()
        self._tmp_folder = 'vmware_temp'
        self._rescue_suffix = '-rescue'
        self._migrate_suffix = '-orig'
        self._datastore_dc_mapping = {}
        self._datastore_browser_mapping = {}
        self._imagecache = imagecache.ImageCacheManager(self._session,
                                                        self._base_folder)
        self._network_api = network.API()

    def _get_base_folder(self):
        # Enable more than one compute node to run on the same host
        if CONF.vmware.cache_prefix:
            base_folder = '%s%s' % (CONF.vmware.cache_prefix,
                                    CONF.image_cache_subdirectory_name)
        # Ensure that the base folder is unique per compute node
        elif CONF.remove_unused_base_images:
            base_folder = '%s%s' % (CONF.my_ip,
                                    CONF.image_cache_subdirectory_name)
        else:
            # Aging disable ensures backward compatibility
            base_folder = CONF.image_cache_subdirectory_name
        return base_folder

    def _extend_virtual_disk(self, instance, requested_size, name, dc_ref):
        service_content = self._session.vim.service_content
        LOG.debug("Extending root virtual disk to %s", requested_size,
                  instance=instance)
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

        LOG.debug("Extended root virtual disk", instance=instance)

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

    def _extend_if_required(self, dc_info, image_info, instance,
                            root_vmdk_path):
        """Increase the size of the root vmdk if necessary."""
        if instance.root_gb * units.Gi > image_info.file_size:
            size_in_kb = instance.root_gb * units.Mi
            self._extend_virtual_disk(instance, size_in_kb,
                                      root_vmdk_path, dc_info.ref)

    def _configure_config_drive(self, instance, vm_ref, dc_info, datastore,
                                injected_files, admin_password, network_info):
        session_vim = self._session.vim
        cookies = session_vim.client.options.transport.cookiejar
        dc_path = vutil.get_inventory_path(session_vim, dc_info.ref)
        uploaded_iso_path = self._create_config_drive(instance,
                                                      injected_files,
                                                      admin_password,
                                                      network_info,
                                                      datastore.name,
                                                      dc_path,
                                                      instance.uuid,
                                                      cookies)
        uploaded_iso_path = datastore.build_path(uploaded_iso_path)
        self._attach_cdrom_to_vm(
            vm_ref, instance,
            datastore.ref,
            str(uploaded_iso_path))

    def _get_instance_metadata(self, context, instance):
        flavor = instance.flavor
        return ('name:%s\n'
                'userid:%s\n'
                'username:%s\n'
                'projectid:%s\n'
                'projectname:%s\n'
                'flavor:name:%s\n'
                'flavor:memory_mb:%s\n'
                'flavor:vcpus:%s\n'
                'flavor:ephemeral_gb:%s\n'
                'flavor:root_gb:%s\n'
                'flavor:swap:%s\n'
                'imageid:%s\n'
                'package:%s\n') % (instance.display_name,
                                   context.user_id,
                                   context.user_name,
                                   context.project_id,
                                   context.project_name,
                                   flavor.name,
                                   flavor.memory_mb,
                                   flavor.vcpus,
                                   flavor.ephemeral_gb,
                                   flavor.root_gb,
                                   flavor.swap,
                                   instance.image_ref,
                                   version.version_string_with_package())

    def _create_folders(self, parent_folder, folder_path):
        folders = folder_path.split('/')
        path_list = []
        for folder in folders:
            path_list.append(folder)
            folder_path = '/'.join(path_list)
            folder_ref = vm_util.folder_ref_cache_get(folder_path)
            if not folder_ref:
                folder_ref = vm_util.create_folder(self._session,
                                                   parent_folder,
                                                   folder)
                vm_util.folder_ref_cache_update(folder_path, folder_ref)
            parent_folder = folder_ref
        return folder_ref

    def _get_folder_name(self, name, id):
        # Maximum folder length must be less than 80 characters.
        # The 'id' length is 36. The maximum prefix for name is 40.
        # We cannot truncate the 'id' as this is unique across OpenStack.
        return '%s (%s)' % (name[:40], id[:36])

    def build_virtual_machine(self, instance, instance_name, image_info,
                              dc_info, datastore, network_info, extra_specs,
                              metadata):
        # Vsettan-only add host parameter
        vif_infos = vmwarevif.get_vif_info(self._session,
                                           self._cluster,
                                           self._host, # Vsettan-only
                                           utils.is_neutron(),
                                           image_info.vif_model,
                                           network_info)

        if extra_specs.storage_policy:
            profile_spec = vm_util.get_storage_profile_spec(
                self._session, extra_specs.storage_policy)
        else:
            profile_spec = None
        # Get the create vm config spec
        client_factory = self._session.vim.client.factory
        config_spec = vm_util.get_vm_create_spec(client_factory,
                                                 instance,
                                                 instance_name, #Vsettan-only
                                                 datastore.name,
                                                 vif_infos,
                                                 extra_specs,
                                                 image_info.os_type,
                                                 profile_spec=profile_spec,
                                                 metadata=metadata,
                                                 ds_ref=datastore.ref) #Vsettan-only

        folder_name = self._get_folder_name('Project',
                                            instance.project_id)
        folder_path = 'OpenStack/%s/Instances' % folder_name
        folder = self._create_folders(dc_info.vmFolder, folder_path)
        # Vsettan-only (prs-related) start
        # Use self._res_pool if it's root resource pool of current host
        if vm_util.is_root_resource_pool(self._session,
                                         resource_Pool=self._res_pool):
            vm_ref = vm_util.create_vm(self._session,
                                       instance,
                                       dc_info.vmFolder,
                                       config_spec,
                                       self._res_pool)
            return vm_ref
        # Vsettan-only (prs-related) end

        # Create the VM
        vm_ref = vm_util.create_vm(self._session, instance, folder,
                                   config_spec, self._root_resource_pool)
        return vm_ref

    def _get_extra_specs(self, flavor, image_meta=None):
        image_meta = image_meta or objects.ImageMeta.from_dict({})
        extra_specs = vm_util.ExtraSpecs()
        for resource in ['cpu', 'memory', 'disk_io', 'vif']:
            for (key, type) in (('limit', int),
                                ('reservation', int),
                                ('shares_level', str),
                                ('shares_share', int)):
                value = flavor.extra_specs.get('quota:' + resource + '_' + key)
                if value:
                    setattr(getattr(extra_specs, resource + '_limits'),
                            key, type(value))
        extra_specs.cpu_limits.validate()
        extra_specs.memory_limits.validate()
        extra_specs.disk_io_limits.validate()
        extra_specs.vif_limits.validate()
        hw_version = flavor.extra_specs.get('vmware:hw_version')
        extra_specs.hw_version = hw_version
        if CONF.vmware.pbm_enabled:
            storage_policy = flavor.extra_specs.get('vmware:storage_policy',
                    CONF.vmware.pbm_default_policy)
            extra_specs.storage_policy = storage_policy
        topology = hardware.get_best_cpu_topology(flavor, image_meta,
                                                  allow_threads=False)
        extra_specs.cores_per_socket = topology.cores
        return extra_specs

    def _get_esx_host_and_cookies(self, datastore, dc_name, file_path):
        hosts = datastore.get_connected_hosts(self._session)
        host = ds_obj.Datastore.choose_host(hosts)
        host_name = self._session._call_method(vutil, 'get_object_property',
                                               host, 'name')
        url = ds_obj.DatastoreURL('https', host_name, file_path, dc_name,
                                  datastore.name)
        cookie_header = url.get_transfer_ticket(self._session, 'PUT')
        name, value = cookie_header.split('=')
        # TODO(rgerganov): this is a hack to emulate cookiejar until we fix
        # oslo.vmware to accept plain http headers
        Cookie = collections.namedtuple('Cookie', ['name', 'value'])
        return host_name, [Cookie(name, value)]

    def _fetch_image_as_file(self, context, vi, image_ds_loc):
        """Download image as an individual file to host via HTTP PUT."""
        session = self._session
        session_vim = session.vim
        cookies = session_vim.client.options.transport.cookiejar

        LOG.debug("Downloading image file data %(image_id)s to "
                  "%(file_path)s on the data store "
                  "%(datastore_name)s",
                  {'image_id': vi.ii.image_id,
                   'file_path': image_ds_loc,
                   'datastore_name': vi.datastore.name},
                  instance=vi.instance)

        # try to get esx cookie to upload
        try:
            dc_name = 'ha-datacenter'
            host, cookies = self._get_esx_host_and_cookies(vi.datastore,
                                                        dc_name,
                                                        image_ds_loc.rel_path)
        except Exception as e:
            LOG.warning(_LW("Get esx cookies failed: %s"), e)
            dc_name = vi.dc_info.name
            host = self._session._host
            cookies = session.vim.client.options.transport.cookiejar

        images.fetch_image(
            context,
            vi.instance,
            host,
            session._port,
            dc_name,
            vi.datastore.name,
            image_ds_loc.rel_path,
            cookies=cookies)

    def _fetch_image_as_vapp(self, context, vi, image_ds_loc):
        """Download stream optimized image to host as a vApp."""

        # The directory of the imported disk is the unique name
        # of the VM use to import it with.
        vm_name = image_ds_loc.parent.basename

        LOG.debug("Downloading stream optimized image %(image_id)s to "
                  "%(file_path)s on the data store "
                  "%(datastore_name)s as vApp",
                  {'image_id': vi.ii.image_id,
                   'file_path': image_ds_loc,
                   'datastore_name': vi.datastore.name},
                  instance=vi.instance)

        image_size = images.fetch_image_stream_optimized(
            context,
            vi.instance,
            self._session,
            vm_name,
            vi.datastore.name,
            vi.dc_info.vmFolder,
            self._root_resource_pool)
        # The size of the image is different from the size of the virtual disk.
        # We want to use the latter. On vSAN this is the only way to get this
        # size because there is no VMDK descriptor.
        vi.ii.file_size = image_size

    def _fetch_image_as_ova(self, context, vi, image_ds_loc):
        """Download root disk of an OVA image as streamOptimized."""

        # The directory of the imported disk is the unique name
        # of the VM use to import it with.
        vm_name = image_ds_loc.parent.basename

        image_size = images.fetch_image_ova(context,
                               vi.instance,
                               self._session,
                               vm_name,
                               vi.datastore.name,
                               vi.dc_info.vmFolder,
                               self._root_resource_pool)
        # The size of the image is different from the size of the virtual disk.
        # We want to use the latter. On vSAN this is the only way to get this
        # size because there is no VMDK descriptor.
        vi.ii.file_size = image_size

    def _prepare_sparse_image(self, vi):
        tmp_dir_loc = vi.datastore.build_path(
                self._tmp_folder, uuidutils.generate_uuid())
        tmp_image_ds_loc = tmp_dir_loc.join(
                vi.ii.image_id, "tmp-sparse.vmdk")
        return tmp_dir_loc, tmp_image_ds_loc

    def _prepare_flat_image(self, vi):
        tmp_dir_loc = vi.datastore.build_path(
                self._tmp_folder, uuidutils.generate_uuid())
        tmp_image_ds_loc = tmp_dir_loc.join(
                vi.ii.image_id, vi.cache_image_path.basename)
        ds_util.mkdir(self._session, tmp_image_ds_loc.parent, vi.dc_info.ref)
        vm_util.create_virtual_disk(
                self._session, vi.dc_info.ref,
                vi.ii.adapter_type,
                vi.ii.disk_type,
                str(tmp_image_ds_loc),
                vi.ii.file_size_in_kb)
        flat_vmdk_name = vi.cache_image_path.basename.replace('.vmdk',
                                                              '-flat.vmdk')
        flat_vmdk_ds_loc = tmp_dir_loc.join(vi.ii.image_id, flat_vmdk_name)
        self._delete_datastore_file(str(flat_vmdk_ds_loc), vi.dc_info.ref)
        return tmp_dir_loc, flat_vmdk_ds_loc

    def _prepare_stream_optimized_image(self, vi):
        vm_name = "%s_%s" % (constants.IMAGE_VM_PREFIX,
                             uuidutils.generate_uuid())
        tmp_dir_loc = vi.datastore.build_path(vm_name)
        tmp_image_ds_loc = tmp_dir_loc.join("%s.vmdk" % tmp_dir_loc.basename)
        return tmp_dir_loc, tmp_image_ds_loc

    def _prepare_iso_image(self, vi):
        tmp_dir_loc = vi.datastore.build_path(
                self._tmp_folder, uuidutils.generate_uuid())
        tmp_image_ds_loc = tmp_dir_loc.join(
                vi.ii.image_id, vi.cache_image_path.basename)
        return tmp_dir_loc, tmp_image_ds_loc

    def _move_to_cache(self, dc_ref, src_folder_ds_path, dst_folder_ds_path):
        try:
            ds_util.file_move(self._session, dc_ref,
                              src_folder_ds_path, dst_folder_ds_path)
        except vexc.FileAlreadyExistsException:
            # Folder move has failed. This may be due to the fact that a
            # process or thread has already completed the operation.
            # Since image caching is synchronized, this can only happen
            # due to action external to the process.
            # In the event of a FileAlreadyExists we continue,
            # all other exceptions will be raised.
            LOG.warning(_LW("Destination %s already exists! Concurrent moves "
                            "can lead to unexpected results."),
                        dst_folder_ds_path)

    def _cache_sparse_image(self, vi, tmp_image_ds_loc):
        tmp_dir_loc = tmp_image_ds_loc.parent.parent
        converted_image_ds_loc = tmp_dir_loc.join(
                vi.ii.image_id, vi.cache_image_path.basename)
        # converts fetched image to preallocated disk
        vm_util.copy_virtual_disk(
                self._session,
                vi.dc_info.ref,
                str(tmp_image_ds_loc),
                str(converted_image_ds_loc))

        self._delete_datastore_file(str(tmp_image_ds_loc), vi.dc_info.ref)

        self._move_to_cache(vi.dc_info.ref,
                            tmp_image_ds_loc.parent,
                            vi.cache_image_folder)
        # The size of the image is different from the size of the virtual
        # disk. We want to use the latter.
        self._update_image_size(vi)

    def _cache_flat_image(self, vi, tmp_image_ds_loc):
        self._move_to_cache(vi.dc_info.ref,
                            tmp_image_ds_loc.parent,
                            vi.cache_image_folder)

    def _cache_stream_optimized_image(self, vi, tmp_image_ds_loc):
        dst_path = vi.cache_image_folder.join("%s.vmdk" % vi.ii.image_id)
        ds_util.mkdir(self._session, vi.cache_image_folder, vi.dc_info.ref)
        try:
            ds_util.disk_move(self._session, vi.dc_info.ref,
                              tmp_image_ds_loc, dst_path)
        except vexc.FileAlreadyExistsException:
            pass

    def _cache_iso_image(self, vi, tmp_image_ds_loc):
        self._move_to_cache(vi.dc_info.ref,
                            tmp_image_ds_loc.parent,
                            vi.cache_image_folder)

    def _get_vm_config_info(self, instance, image_info,
                            extra_specs,
                            instance_name=None,
                            storage_pod=None): # Vsettan-only
        """Captures all relevant information from the spawn parameters."""

        if (instance.root_gb != 0 and
                image_info.file_size > instance.root_gb * units.Gi):
            reason = _("Image disk size greater than requested disk size")
            raise exception.InstanceUnacceptable(instance_id=instance.uuid,
                                                 reason=reason)
        allowed_ds_types = ds_util.get_allowed_datastore_types(
            image_info.disk_type)
        datastore = ds_util.get_datastore(self._session,
                                          self._cluster,
                                          # Vsettan-only begin
                                          self._host,
                                          storage_pod,
                                          # Vsettan-only end
                                          self._datastore_regex,
                                          extra_specs.storage_policy,
                                          allowed_ds_types)
        dc_info = self.get_datacenter_ref_and_name(datastore.ref)

        return VirtualMachineInstanceConfigInfo(instance,
                                                instance_name, #Vsettan-only
                                                image_info,
                                                datastore,
                                                dc_info,
                                                self._imagecache,
                                                extra_specs)

    #Vsettan-only start
    #This implementation requires a vsphere URL meaning that the image is already
    #on a VMware datastore:
    #ex: vsphere://server_host/folder/file_path?dcPath=dc_path&dsName=ds_name
    def _parse_location_info(self, location_url):
        (scheme, server_host, file_path, params, query, fragment) = (
            urlparse.urlparse(location_url))
        # src file_path
        if not query:
            file_path = file_path.split('?')
            if len(file_path) > 1:
                query = file_path[1]
                file_path = file_path[0]
            else:
                msg = (_("Location URL %s must contain a file "
                         "path") % location_url)
                raise exception.InvalidInput(reason=msg)
        if not file_path.startswith(DS_URL_PREFIX):
            msg = (_("Location URL %(url)s must "
                     "start with %(prefix)s") % {'url': location_url, 'prefix': DS_URL_PREFIX})
            raise exception.InvalidInput(reason=msg)
        file_path = file_path[len(DS_URL_PREFIX):]
        # src datacenter name
        params = urlparse.parse_qs(query)
        dc_path = params.get('dcPath')
        if dc_path and len(dc_path) > 0:
            dc_path = dc_path.pop()
        else:
            msg = (_("Location URL %(url)s must contain a datacenter path") %
                  location_url)
            raise exception.InvalidInput(reason=msg)
        # src datastore
        ds_name = params.get('dsName')
        if ds_name and len(ds_name) > 0:
            ds_name = ds_name.pop()
        else:
            msg = (_("Location URL %(url)s must contain a datastore name") %
                  location_url)
            raise exception.InvalidInput(reason=msg)
        return scheme, dc_path, ds_name, file_path

    def _get_location_info(self, context, image_location_url):
        try:
            store_type, src_dc_path, src_ds_name, src_file_path = (
                    self._parse_location_info(image_location_url))
        except Exception:
            LOG.error(_("Unable parse location url %(url)s for "
                     "image %(image)s"), {'url': image_location_url,
                            'image': image_id})
            return

        if src_dc_path is None or src_ds_name is None or src_file_path is None:
            LOG.error(_("Cannot copy image %(image)s with datacenter "
                "%(dc_path)s, datastore %(ds_name)s and file location "
                "%(file)s"), {'image': image_id,
                        'dc_path': src_dc_path,
                        'ds_name': src_ds_name,
                        'file': src_file_path})
            return

        src_file_path = '[%s] %s' % (src_ds_name, src_file_path)
        return store_type, src_file_path
    #Vsettan-only end

    def _get_image_callbacks(self, vi):
        disk_type = vi.ii.disk_type

        if vi.ii.is_ova:
            image_fetch = self._fetch_image_as_ova
        elif disk_type == constants.DISK_TYPE_STREAM_OPTIMIZED:
            image_fetch = self._fetch_image_as_vapp
        else:
            image_fetch = self._fetch_image_as_file

        if vi.ii.is_iso:
            image_prepare = self._prepare_iso_image
            image_cache = self._cache_iso_image
        elif disk_type == constants.DISK_TYPE_SPARSE:
            image_prepare = self._prepare_sparse_image
            image_cache = self._cache_sparse_image
        elif disk_type == constants.DISK_TYPE_STREAM_OPTIMIZED:
            image_prepare = self._prepare_stream_optimized_image
            image_cache = self._cache_stream_optimized_image
        elif disk_type in constants.SUPPORTED_FLAT_VARIANTS:
            image_prepare = self._prepare_flat_image
            image_cache = self._cache_flat_image
        else:
            reason = _("disk type '%s' not supported") % disk_type
            raise exception.InvalidDiskInfo(reason=reason)
        return image_prepare, image_fetch, image_cache

    def _fetch_image_if_missing(self, context, vi):
        image_prepare, image_fetch, image_cache = self._get_image_callbacks(vi)
        LOG.debug("Processing image %s", vi.ii.image_id, instance=vi.instance)

        with lockutils.lock(str(vi.cache_image_path),
                            lock_file_prefix='nova-vmware-fetch_image'):
            self.check_cache_folder(vi.datastore.name, vi.datastore.ref)
            ds_browser = self._get_ds_browser(vi.datastore.ref)
            if not ds_util.file_exists(self._session, ds_browser,
                                       vi.cache_image_folder,
                                       vi.cache_image_path.basename):
                LOG.debug("Preparing fetch location", instance=vi.instance)
                tmp_dir_loc, tmp_image_ds_loc = image_prepare(vi)
                LOG.debug("Fetch image to %s", tmp_image_ds_loc,
                          instance=vi.instance)
                #Vsettan-only start
                image_id = vi.ii.image_id
                image_detail = {}
                try:
                    image_detail = IMAGE_SERVICE.show(context, image_id, True)
                    LOG.debug("image detail information is %s", image_detail)
                except Exception as e:
                    LOG.error(("The glance service does not return image details,"
                               "reason: %s"), e)
                image_location_url = image_detail.get('direct_url', None)
                backend_scheme = 'file'
                vsphere_string = 'vsphere://'
                if image_location_url and vsphere_string in image_location_url:
                    backend_scheme, glance_ds_path = self._get_location_info(context, image_location_url)

                if backend_scheme == 'vsphere':
                    tmp_image_ds_dir = tmp_image_ds_loc.rel_path[:tmp_image_ds_loc.rel_path.rfind('/')]
                    self._create_folder_if_missing(vi.datastore.name, vi.datastore.ref, tmp_image_ds_dir)
                    ds_util.file_copy(self._session, glance_ds_path, vi.dc_info.ref,
                                      tmp_image_ds_loc, vi.dc_info.ref)
                else:
                    image_fetch(context, vi, tmp_image_ds_loc)
                #Vsettan-only end
                LOG.debug("Caching image", instance=vi.instance)
                image_cache(vi, tmp_image_ds_loc)
                LOG.debug("Cleaning up location %s", str(tmp_dir_loc),
                          instance=vi.instance)
                self._delete_datastore_file(str(tmp_dir_loc), vi.dc_info.ref)

    def _create_and_attach_thin_disk(self, instance, vm_ref, dc_info, size,
                                     adapter_type, path):
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
                at = eph.get('disk_bus') or adapter_type
                filename = vm_util.get_ephemeral_name(idx)
                path = str(ds_obj.DatastorePath(datastore.name, folder,
                                                filename))
                self._create_and_attach_thin_disk(instance, vm_ref, dc_info,
                                                  size, at, path)
        # There may be block devices defined but no ephemerals. In this case
        # we need to allocate an ephemeral disk if required
        if not ephemerals and instance.ephemeral_gb:
            size = instance.ephemeral_gb * units.Mi
            filename = vm_util.get_ephemeral_name(0)
            path = str(ds_obj.DatastorePath(datastore.name, folder,
                                             filename))
            self._create_and_attach_thin_disk(instance, vm_ref, dc_info, size,
                                              adapter_type, path)

    #Vsettan-only start
    def _get_storage_pod(self, instance):
        conf_pod_name = CONF.vmware.datastore_cluster_name
        flavor = instance.flavor
        pod_name = flavor.get('extra_specs').get('vmware:datastore_cluster_name',
                                                 conf_pod_name)
        pod = None
        if pod_name == conf_pod_name:
            pod = self._storage_pod
        else:
            pod = ds_util.get_storage_pod_ref_by_name(self._session, pod_name)
            if pod_name is not None and pod is None:
                LOG.warn(_("StoragePod %s is not found") % pod_name)
        return pod

    def _is_template_image(self, context, instance, image_meta):
        """Check if the image is a template image from vcenter.
        """
        image_ref = instance.get('image_ref')
        template_name = None
        template_instanceuuid = None
        is_template = False
        if image_ref:
            image_size, image_properties = images.get_vmdk_size_and_properties(
                    context, image_ref, instance)
            template_name = image_properties.get("template_name")
            template_instanceuuid = image_properties.get("template_instanceuuid")
            is_template = template_name or template_instanceuuid
        return is_template
    #Vsettan-only end

    def _create_swap(self, bdi, instance, vm_ref, dc_info, datastore,
                     folder, adapter_type):
        swap = None
        filename = "swap.vmdk"
        path = str(ds_obj.DatastorePath(datastore.name, folder, filename))
        if bdi is not None:
            swap = driver.block_device_info_get_swap(bdi)
            if driver.swap_is_usable(swap):
                size = swap['swap_size'] * units.Ki
                self._create_and_attach_thin_disk(instance, vm_ref, dc_info,
                                                  size, adapter_type, path)
            else:
                # driver.block_device_info_get_swap returns
                # {'device_name': None, 'swap_size': 0} if swap is None
                # in block_device_info.  If block_device_info does not contain
                # a swap device, we need to reset swap to None, so we can
                # extract the swap_size from the instance's flavor.
                swap = None

        size = instance.flavor.swap * units.Ki
        if not swap and size > 0:
            self._create_and_attach_thin_disk(instance, vm_ref, dc_info, size,
                                              adapter_type, path)

    def _update_vnic_index(self, context, instance, network_info):
        if network_info:
            for index, vif in enumerate(network_info):
                self._network_api.update_instance_vnic_index(
                    context, instance, vif, index)

    def _update_image_size(self, vi):
        """Updates the file size of the specified image."""
        # The size of the Glance image is different from the deployed VMDK
        # size for sparse, streamOptimized and OVA images. We need to retrieve
        # the size of the flat VMDK and update the file_size property of the
        # image. This ensures that further operations involving size checks
        # and disk resizing will work as expected.
        ds_browser = self._get_ds_browser(vi.datastore.ref)
        flat_file = "%s-flat.vmdk" % vi.ii.image_id
        new_size = ds_util.file_size(self._session, ds_browser,
                                     vi.cache_image_folder, flat_file)
        if new_size is not None:
            vi.ii.file_size = new_size

    def spawn(self, context, instance, image_meta, injected_files,
              admin_password, network_info, block_device_info=None,
              instance_name=None, power_on=True):
        client_factory = self._session.vim.client.factory
        #Vsettan-only start
        if instance_name is None:
            instance_name = vm_util.get_vm_name_for_vcenter(instance)
        storage_pod = self._get_storage_pod(instance)
        isTemplate = self._is_template_image(context, instance, image_meta)

        if isTemplate:
            vmTemplate = template.VMwareVMTemplate(self._session, self._virtapi,
                                      self._volumeops, cluster=self._cluster,
                                      storage_pod=storage_pod,
                                      datastore_regex=self._datastore_regex,
                                      res_pool=self._res_pool)
            vm_ref = vmTemplate.spawn_from_template(context, instance,
                                                    image_meta, injected_files,
                                                    admin_password,
                                                    network_info,
                                                    block_device_info,
                                                    instance_name,
                                                    power_on)
            # Set the machine.id parameter of the instance to inject
            # the NIC configuration inside the VM
            if CONF.flat_injected:
                self._set_machine_id(client_factory, instance, network_info)

            # Set the vnc configuration of the instance, vnc port starts from 5900
            if CONF.vnc_enabled:
                self._get_and_set_vnc_config(client_factory, instance, vm_ref)
            return
        #Vsettan-only end

        image_info = images.VMwareImage.from_image(instance.image_ref,
                                                   image_meta)
        extra_specs = self._get_extra_specs(instance.flavor, image_meta)

        vi = self._get_vm_config_info(instance, image_info,
                                      extra_specs,
                                      instance_name,
                                      storage_pod) # Vsettan-only add pod

        metadata = self._get_instance_metadata(context, instance)
        # Creates the virtual machine. The virtual machine reference returned
        # is unique within Virtual Center.
        vm_ref = self.build_virtual_machine(instance,
                                            vi.instance_name,
                                            image_info,
                                            vi.dc_info,
                                            vi.datastore,
                                            network_info,
                                            extra_specs,
                                            metadata)

        # Cache the vm_ref. This saves a remote call to the VC. This uses the
        # instance uuid.
        vm_util.vm_ref_cache_update(instance.uuid, vm_ref)

        # Update the Neutron VNIC index
        self._update_vnic_index(context, instance, network_info)

        # Set the machine.id parameter of the instance to inject
        # the NIC configuration inside the VM
        if CONF.flat_injected:
            self._set_machine_id(client_factory, instance, network_info,
                                vm_ref=vm_ref)

        # Set the vnc configuration of the instance, vnc port starts from 5900
        if CONF.vnc.enabled:
            self._get_and_set_vnc_config(client_factory, instance, vm_ref)

        block_device_mapping = []
        if block_device_info is not None:
            block_device_mapping = driver.block_device_info_get_mapping(
                block_device_info)

        if instance.image_ref:
            self._imagecache.enlist_image(
                    image_info.image_id, vi.datastore, vi.dc_info.ref)
            self._fetch_image_if_missing(context, vi)

            if image_info.is_iso:
                self._use_iso_image(vm_ref, vi)
            elif image_info.linked_clone:
                self._use_disk_image_as_linked_clone(vm_ref, vi)
            else:
                self._use_disk_image_as_full_clone(vm_ref, vi)

        if block_device_mapping:
            msg = "Block device information present: %s" % block_device_info
            # NOTE(mriedem): block_device_info can contain an auth_password
            # so we have to scrub the message before logging it.
            LOG.debug(strutils.mask_password(msg), instance=instance)

            # Before attempting to attach any volume, make sure the
            # block_device_mapping (i.e. disk_bus) is valid
            self._is_bdm_valid(block_device_mapping)

            for disk in block_device_mapping:
                connection_info = disk['connection_info']
                adapter_type = disk.get('disk_bus') or vi.ii.adapter_type

                # TODO(hartsocks): instance is unnecessary, remove it
                # we still use instance in many locations for no other purpose
                # than logging, can we simplify this?
                if disk.get('boot_index') == 0:
                    self._volumeops.attach_root_volume(connection_info,
                        instance, vi.datastore.ref, adapter_type)
                else:
                    self._volumeops.attach_volume(connection_info,
                        instance, adapter_type)

        # Create ephemeral disks
        self._create_ephemeral(block_device_info, instance, vm_ref,
                               vi.dc_info, vi.datastore, instance.uuid,
                               vi.ii.adapter_type)
        self._create_swap(block_device_info, instance, vm_ref, vi.dc_info,
                          vi.datastore, instance.uuid, vi.ii.adapter_type)

        if configdrive.required_by(instance):
            self._configure_config_drive(
                    instance, vm_ref, vi.dc_info, vi.datastore,
                    injected_files, admin_password, network_info)

        # Rename the VM. This is done after the spec is created to ensure
        # that all of the files for the instance are under the directory
        # 'uuid' of the instance
        vm_util.rename_vm(self._session, vm_ref, instance)

        if power_on:
            vm_util.power_on_instance(self._session, instance, vm_ref=vm_ref)

    def _is_bdm_valid(self, block_device_mapping):
        """Checks if the block device mapping is valid."""
        valid_bus = (constants.DEFAULT_ADAPTER_TYPE,
                     constants.ADAPTER_TYPE_BUSLOGIC,
                     constants.ADAPTER_TYPE_IDE,
                     constants.ADAPTER_TYPE_LSILOGICSAS,
                     constants.ADAPTER_TYPE_PARAVIRTUAL)

        for disk in block_device_mapping:
            adapter_type = disk.get('disk_bus')
            if (adapter_type is not None and adapter_type not in valid_bus):
                raise exception.UnsupportedHardware(model=adapter_type,
                                                    virt="vmware")

    def _create_config_drive(self, instance, injected_files, admin_password,
                             network_info, data_store_name, dc_name,
                             upload_folder, cookies):
        if CONF.config_drive_format != 'iso9660':
            reason = (_('Invalid config_drive_format "%s"') %
                      CONF.config_drive_format)
            raise exception.InstancePowerOnFailure(reason=reason)

        LOG.info(_LI('Using config drive for instance'), instance=instance)
        extra_md = {}
        if admin_password:
            extra_md['admin_pass'] = admin_password

        inst_md = instance_metadata.InstanceMetadata(instance,
                                                     content=injected_files,
                                                     extra_md=extra_md,
                                                     network_info=network_info)
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
                LOG.error(_LE('Creating config drive failed with error: %s'),
                          e, instance=instance)

    def _attach_cdrom_to_vm(self, vm_ref, instance,
                            datastore, file_path):
        """Attach cdrom to VM by reconfiguration."""
        client_factory = self._session.vim.client.factory
        devices = self._session._call_method(vim_util,
                                    "get_dynamic_property",
                                    vm_ref,
                                    "VirtualMachine",
                                    "config.hardware.device")
        (controller_key, unit_number,
         controller_spec) = vm_util.allocate_controller_key_and_unit_number(
                                                    client_factory,
                                                    devices,
                                                    constants.ADAPTER_TYPE_IDE)
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

    def _create_vm_snapshot(self, instance, vm_ref):
        LOG.debug("Creating Snapshot of the VM instance", instance=instance)
        snapshot_task = self._session._call_method(
                    self._session.vim,
                    "CreateSnapshot_Task", vm_ref,
                    name="%s-snapshot" % instance.uuid,
                    description="Taking Snapshot of the VM",
                    memory=False,
                    quiesce=True)
        self._session._wait_for_task(snapshot_task)
        LOG.debug("Created Snapshot of the VM instance", instance=instance)
        task_info = self._session._call_method(vim_util,
                                               "get_dynamic_property",
                                               snapshot_task,
                                               "Task", "info")
        snapshot = task_info.result
        return snapshot

    @retry_if_task_in_progress
    def _delete_vm_snapshot(self, instance, vm_ref, snapshot):
        LOG.debug("Deleting Snapshot of the VM instance", instance=instance)
        delete_snapshot_task = self._session._call_method(
                    self._session.vim,
                    "RemoveSnapshot_Task", snapshot,
                    removeChildren=False, consolidate=True)
        self._session._wait_for_task(delete_snapshot_task)
        LOG.debug("Deleted Snapshot of the VM instance", instance=instance)

    def _create_linked_clone_from_snapshot(self, instance,
                                           vm_ref, snapshot_ref, dc_info):
        """Create linked clone VM to be deployed to same ds as source VM
        """
        client_factory = self._session.vim.client.factory
        rel_spec = vm_util.relocate_vm_spec(
                client_factory,
                datastore=None,
                host=None,
                disk_move_type="createNewChildDiskBacking")
        clone_spec = vm_util.clone_vm_spec(client_factory, rel_spec,
                power_on=False, snapshot=snapshot_ref, template=True)
        vm_name = "%s_%s" % (constants.SNAPSHOT_VM_PREFIX,
                             uuidutils.generate_uuid())

        LOG.debug("Creating linked-clone VM from snapshot", instance=instance)
        vm_clone_task = self._session._call_method(
                                self._session.vim,
                                "CloneVM_Task",
                                vm_ref,
                                folder=dc_info.vmFolder,
                                name=vm_name,
                                spec=clone_spec)
        self._session._wait_for_task(vm_clone_task)
        LOG.info(_LI("Created linked-clone VM from snapshot"),
                 instance=instance)
        task_info = self._session._call_method(vim_util,
                                               "get_dynamic_property",
                                               vm_clone_task,
                                               "Task", "info")
        return task_info.result

    # Vsettan-ONLY START snapshot to template
    def get_disk_size_in_byte(self, device):
        size = 0;
        if hasattr(device, 'capacityInBytes'):
           size = int(device.capacityInBytes)
        else:
           size = int(device.capacityInKB) * 1024
        return size

    def _snapshot_template(self, context, instance, image_id, image, update_task_state):
        """Create snapshot from a running VM instance to VCenter template
        """
        vm_ref = vm_util.get_vm_ref(self._session, instance)
        ds_ref = ds_util.get_datastore(
                            self._session, self._cluster,
                            datastore_regex=self._datastore_regex).ref
        dc_info = self.get_datacenter_ref_and_name(ds_ref)
        folder = dc_info.vmFolder
        tmpl_name = image_id
        image_name = image.get('name')
        if image_name and len(image_name.strip()) > 0:
            tmpl_name = image_name[:43] + '-' + image_id

        vm_util.clone_vmref_to_template(self._session, tmpl_name,
                                        vm_ref, None, None, folder)

        # Update Glance image
        update_task_state(task_state=task_states.IMAGE_PENDING_UPLOAD)
        prop_list = ['config.name','config.template','config.instanceUuid',
                     'config.uuid','config.guestId','config.guestFullName',
                     'config.hardware.device','config.files.vmPathName']
        tmpl_ref = vm_util.get_vm_ref_from_name(self._session, tmpl_name)
        props = self._session._call_method(vim_util, "get_object_properties",
                        None, tmpl_ref, "VirtualMachine", prop_list)
        query = vm_util.get_values_from_object_properties(self._session, props)

        tmpl_url = ('http://' + CONF.vmware.host_ip +
                    query['config.files.vmPathName'].replace("[","/").replace('] ',"/").replace(" ","_"))
        size = 0
        root_disk_size = 0
        hw_vif_model = None
        vmware_adaptertype = None
        vmware_disktype = None
        nic_num = 0
        SCSI_DEVICE_TRANSFORM = {'VirtualLsiLogicSASController':'lsiLogicsas',
                                 'ParaVirtualSCSIController':'paraVirtualscsi',
                                 'VirtualBusLogicController':'busLogic',
                                 'VirtualLsiLogicController':'lsiLogic'}
        VNIC_TYPES = ['VirtualE1000', 'VirtualE1000e', 'VirtualPCNet32', 'VirtualEthernetCard',
                      'VirtualVmxnet', 'VirtualVmxnet2', 'VirtualVmxnet3']

        devices = query['config.hardware.device']
        if devices.__class__.__name__ == "ArrayOfVirtualDevice":
            devices = devices.VirtualDevice
        for device in devices:
            if device.__class__.__name__ in VNIC_TYPES:
                nic_num += 1
            if (device.__class__.__name__ == 'VirtualDisk' and
                device.deviceInfo.label == "Hard disk 1"):
                root_disk_size = self.get_disk_size_in_byte(device)
            if (device.key == 1000 and
                device.__class__.__name__ in SCSI_DEVICE_TRANSFORM.keys()):
                vmware_adaptertype = SCSI_DEVICE_TRANSFORM[
                        device.__class__.__name__]
            if (device.key >= 2000 and device.key < 3000 and
                device.__class__.__name__ == 'VirtualDisk'):
                if device.backing.thinProvisioned:
                    vmware_disktype = 'thin'
                else:
                    vmware_disktype = 'preallocated'
                size += self.get_disk_size_in_byte(device)
            if (device.key >= 3000 and device.key < 4000 and
                device.__class__.__name__ == 'VirtualDisk'):
                vmware_adaptertype = 'ide'
                size += self.get_disk_size_in_byte(device)
            if device.key == 4000:
                hw_vif_model = device.__class__.__name__

        metadata = {'size': 0,
                    'container_format': 'bare',
                    'disk_format': 'vmdk',
                    'is_public': True,
                    'properties': {
                        'hw_vif_model': hw_vif_model,
                        'size': size,
                        'root_disk_size': root_disk_size,
                        'nic_num': nic_num,
                        'template_guestfullname': query['config.guestFullName'],
                        'template_instanceuuid': query['config.instanceUuid'],
                        'template_name': query['config.name'],
                        'vcenter_ip': CONF.vmware.host_ip,
                        'vmware_adaptertype': vmware_adaptertype,
                        'vmware_disktype': vmware_disktype,
                        'vmware_ostype': query['config.guestId'],
                        'vmware_path': tmpl_url,
                        'vmware_template': query['config.template']
                        }
                   }

        update_task_state(task_state=task_states.IMAGE_UPLOADING,
                          expected_state=task_states.IMAGE_PENDING_UPLOAD)
        # Upload an empty file to Glance
        with file('/dev/null', 'r') as image_file:
            self.image_api.update(context,
                                  image_id,
                                  metadata,
                                  image_file)
        # Update image size attribute
        metadata = {'size': size}
        self.image_api.update(context,
                              image_id,
                              metadata)
    # Vsettan-ONLY STOP

    def snapshot(self, context, instance, image_id, update_task_state):
        """Create snapshot from a running VM instance.

        Steps followed are:

        1. Get the name of the vmdk file which the VM points to right now.
           Can be a chain of snapshots, so we need to know the last in the
           chain.
        2. Create the snapshot. A new vmdk is created which the VM points to
           now. The earlier vmdk becomes read-only.
        3. Creates a linked clone VM from the snapshot
        4. Exports the disk in the link clone VM as a streamOptimized disk.
        5. Delete the linked clone VM
        6. Deletes the snapshot in original instance.
        """

        # Vsettan-ONLY START snapshot to template
        image = self.image_api.get(context, image_id)
        image_ref = instance.image_ref
        vmware_template = None
        template_instanceuuid = None
        template_name = None
        properties = image.get('properties')
        if properties:
            vmware_template = properties.get('vmware_template')
            template_instanceuuid = properties.get('template_instanceuuid')
            template_name = properties.get('template_name')
        snapshot_image_format = CONF.vmware.snapshot_image_format
        # If VM is booted from VMDK, can snapsht it to VMDK or templae.
        # If VM is booted from template, can not snapsht it to VMDK
        if ((template_instanceuuid or template_name) or    #Boot from template
            ((vmware_template == 'True') or    #Boot from VMDK and snpshot to template
             (vmware_template is None and snapshot_image_format == 'template'))):
                self._snapshot_template(context, instance, image_id, image,
                                        update_task_state)
                return

        # Vsettan-ONLY STOP

        vm_ref = vm_util.get_vm_ref(self._session, instance)

        def _get_vm_and_vmdk_attribs():
            # Get the vmdk info that the VM is pointing to
            vmdk = vm_util.get_vmdk_info(self._session, vm_ref,
                                              instance.uuid)
            if not vmdk.path:
                LOG.debug("No root disk defined. Unable to snapshot.",
                          instance=instance)
                raise error_util.NoRootDiskDefined()

            lst_properties = ["datastore", "summary.config.guestId"]
            props = self._session._call_method(vutil,
                                               "get_object_properties_dict",
                                               vm_ref,
                                               lst_properties)
            os_type = props['summary.config.guestId']
            datastores = props['datastore']
            return (vmdk, datastores, os_type)

        vmdk, datastores, os_type = _get_vm_and_vmdk_attribs()
        ds_ref = datastores.ManagedObjectReference[0]
        dc_info = self.get_datacenter_ref_and_name(ds_ref)

        update_task_state(task_state=task_states.IMAGE_PENDING_UPLOAD)

        # TODO(vui): convert to creating plain vm clone and uploading from it
        # instead of using live vm snapshot.
        snapshot_ref = self._create_vm_snapshot(instance, vm_ref)

        update_task_state(task_state=task_states.IMAGE_UPLOADING,
                          expected_state=task_states.IMAGE_PENDING_UPLOAD)
        snapshot_vm_ref = None

        try:
            # Create a temporary VM (linked clone from snapshot), then export
            # the VM's root disk to glance via HttpNfc API
            snapshot_vm_ref = self._create_linked_clone_from_snapshot(
                instance, vm_ref, snapshot_ref, dc_info)
            images.upload_image_stream_optimized(
                context, image_id, instance, self._session, vm=snapshot_vm_ref,
                vmdk_size=vmdk.capacity_in_bytes)
        finally:
            if snapshot_vm_ref:
                vm_util.destroy_vm(self._session, instance, snapshot_vm_ref)
            # Deleting the snapshot after destroying the temporary VM created
            # based on it allows the instance vm's disks to be consolidated.
            # TODO(vui) Add handling for when vmdk volume is attached.
            self._delete_vm_snapshot(instance, vm_ref, snapshot_ref)

    def reboot(self, instance, network_info, reboot_type="SOFT"):
        """Reboot a VM instance."""
        vm_ref = vm_util.get_vm_ref(self._session, instance)
        lst_properties = ["summary.guest.toolsStatus", "runtime.powerState",
                          "summary.guest.toolsRunningStatus"]
        props = self._session._call_method(vutil,
                                           "get_object_properties_dict",
                                           vm_ref,
                                           lst_properties)
        pwr_state = props['runtime.powerState']
        tools_status = props['summary.guest.toolsStatus']
        tools_running_status = props['summary.guest.toolsRunningStatus']

        # Raise an exception if the VM is not powered On.
        if pwr_state not in ["poweredOn"]:
            reason = _("instance is not powered on")
            raise exception.InstanceRebootFailure(reason=reason)

        # If latest vmware tools are installed in the VM, and that the tools
        # are running, then only do a guest reboot. Otherwise do a hard reset.
        if (tools_status == "toolsOk" and
                tools_running_status == "guestToolsRunning" and
                reboot_type == "SOFT"):
            LOG.debug("Rebooting guest OS of VM", instance=instance)
            self._session._call_method(self._session.vim, "RebootGuest",
                                       vm_ref)
            LOG.debug("Rebooted guest OS of VM", instance=instance)
        else:
            LOG.debug("Doing hard reboot of VM", instance=instance)
            reset_task = self._session._call_method(self._session.vim,
                                                    "ResetVM_Task", vm_ref)
            self._session._wait_for_task(reset_task)
            LOG.debug("Did hard reboot of VM", instance=instance)

    def _destroy_instance(self, instance, destroy_disks=True, instance_name=None): #Vsettan-only
        # Destroy a VM instance
        try:
            vm_ref = vm_util.get_vm_ref_from_name(self._session, instance_name) or \
                     vm_util.get_vm_ref(self._session, instance)  # Vsettan-only
            lst_properties = ["config.files.vmPathName", "runtime.powerState",
                              "datastore"]
            props = self._session._call_method(vutil,
                                               "get_object_properties_dict",
                                               vm_ref,
                                               lst_properties)
            pwr_state = props['runtime.powerState']

            vm_config_pathname = props.get('config.files.vmPathName')
            vm_ds_path = None
            if vm_config_pathname is not None:
                vm_ds_path = ds_obj.DatastorePath.parse(
                        vm_config_pathname)

            # Power off the VM if it is in PoweredOn state.
            if pwr_state == "poweredOn":
                vm_util.power_off_instance(self._session, instance, vm_ref)

            # Un-register the VM
            try:
                LOG.debug("Unregistering the VM", instance=instance)
                self._session._call_method(self._session.vim,
                                           "UnregisterVM", vm_ref)
                LOG.debug("Unregistered the VM", instance=instance)
            except Exception as excep:
                LOG.warning(_LW("In vcmvmwareapi:vmops:_destroy_instance, got "
                                "this exception while un-registering the VM: "
                                "%s"), excep)
            # Delete the folder holding the VM related content on
            # the datastore.
            if destroy_disks and vm_ds_path:
                try:
                    dir_ds_compliant_path = vm_ds_path.parent
                    LOG.debug("Deleting contents of the VM from "
                              "datastore %(datastore_name)s",
                              {'datastore_name': vm_ds_path.datastore},
                              instance=instance)
                    ds_ref_ret = props['datastore']
                    ds_ref = ds_ref_ret.ManagedObjectReference[0]
                    dc_info = self.get_datacenter_ref_and_name(ds_ref)
                    ds_util.file_delete(self._session,
                                        dir_ds_compliant_path,
                                        dc_info.ref)
                    LOG.debug("Deleted contents of the VM from "
                              "datastore %(datastore_name)s",
                              {'datastore_name': vm_ds_path.datastore},
                              instance=instance)
                except Exception:
                    LOG.warning(_LW("In vcmvmwareapi:vmops:_destroy_instance, "
                                    "exception while deleting the VM contents "
                                    "from the disk"), exc_info=True)
        except exception.InstanceNotFound:
            LOG.warning(_LW('Instance does not exist on backend'),
                        instance=instance)
        except Exception:
            LOG.exception(_LE('Destroy instance failed'),
                          instance=instance)
        finally:
            vm_util.vm_ref_cache_delete(instance.uuid)
            vm_util.vm_ref_cache_delete(instance.name)

    #Vsettan-only start
    def _is_template(self, instance):
        try:
            vm_ref = vm_util.get_vm_ref(self._session, instance)
            props = self._session._call_method(vim_util,
                        "get_object_properties",
                        None, vm_ref, "VirtualMachine", ["config.template"])
            if props and props.objects[0].propSet[0].name == "config.template":
                return props.objects[0].propSet[0].val
            return False
        except exception.InstanceNotFound:
            return False

    #Vsettan-only end

    def destroy(self, instance, destroy_disks=True):
        """Destroy a VM instance.

        Steps followed for each VM are:
        1. Power off, if it is in poweredOn state.
        2. Un-register.
        3. Delete the contents of the folder holding the VM related data.
        """
        if instance.task_state == task_states.RESIZE_REVERTING:
            return
        #Vsettan-only start
        if self._is_template(instance):
            LOG.debug(_("Instance is a template, leave it in vCenter."),
                      instance=instance)
            return
        instance_name = vm_util.get_vm_name_for_vcenter(instance)
        #Vsettan-only end

        # If there is a rescue VM then we need to destroy that one too.
        LOG.debug("Destroying instance", instance=instance)
        if instance.vm_state == vm_states.RESCUED:
            LOG.debug("Rescue VM configured", instance=instance)
            try:
                self.unrescue(instance, power_on=False)
                LOG.debug("Rescue VM destroyed", instance=instance)
            except Exception:
                rescue_name = instance_name + self._rescue_suffix #Vsettan-only
                self._destroy_instance(instance,
                                       destroy_disks=destroy_disks,
                                       instance_name=rescue_name)
        self._destroy_instance(instance, destroy_disks=destroy_disks,
                               instance_name=instance_name) #Vsettan-only
        LOG.debug("Instance destroyed", instance=instance)

    def pause(self, instance):
        msg = _("pause not supported for vcmvmwareapi")
        raise NotImplementedError(msg)

    def unpause(self, instance):
        msg = _("unpause not supported for vcmvmwareapi")
        raise NotImplementedError(msg)

    def suspend(self, instance):
        """Suspend the specified instance."""
        vm_ref = vm_util.get_vm_ref(self._session, instance)
        pwr_state = self._session._call_method(vim_util,
                    "get_dynamic_property", vm_ref,
                    "VirtualMachine", "runtime.powerState")
        # Only PoweredOn VMs can be suspended.
        if pwr_state == "poweredOn":
            LOG.debug("Suspending the VM", instance=instance)
            suspend_task = self._session._call_method(self._session.vim,
                    "SuspendVM_Task", vm_ref)
            self._session._wait_for_task(suspend_task)
            LOG.debug("Suspended the VM", instance=instance)
        # Raise Exception if VM is poweredOff
        elif pwr_state == "poweredOff":
            reason = _("instance is powered off and cannot be suspended.")
            raise exception.InstanceSuspendFailure(reason=reason)
        else:
            LOG.debug("VM was already in suspended state. So returning "
                      "without doing anything", instance=instance)

    def resume(self, instance):
        """Resume the specified instance."""
        vm_ref = vm_util.get_vm_ref(self._session, instance)
        pwr_state = self._session._call_method(vim_util,
                                     "get_dynamic_property", vm_ref,
                                     "VirtualMachine", "runtime.powerState")
        if pwr_state.lower() == "suspended":
            LOG.debug("Resuming the VM", instance=instance)
            suspend_task = self._session._call_method(
                                        self._session.vim,
                                       "PowerOnVM_Task", vm_ref)
            self._session._wait_for_task(suspend_task)
            LOG.debug("Resumed the VM", instance=instance)
        else:
            reason = _("instance is not in a suspended state")
            raise exception.InstanceResumeFailure(reason=reason)

    def _get_rescue_device(self, instance, vm_ref):
        hardware_devices = self._session._call_method(vim_util,
                        "get_dynamic_property", vm_ref,
                        "VirtualMachine", "config.hardware.device")
        return vm_util.find_rescue_device(hardware_devices,
                                          instance)

    def rescue(self, context, instance, network_info, image_meta):
        """Rescue the specified instance.

        Attach the image that the instance was created from and boot from it.
        """
        vm_ref = vm_util.get_vm_ref(self._session, instance)

        # Get the root disk vmdk object
        vmdk = vm_util.get_vmdk_info(self._session, vm_ref,
                                     uuid=instance.uuid)
        ds_ref = vmdk.device.backing.datastore
        datastore = ds_util.get_datastore_by_ref(self._session, ds_ref)
        dc_info = self.get_datacenter_ref_and_name(datastore.ref)

        # Get the image details of the instance
        image_info = images.VMwareImage.from_image(image_meta.id,
                                                   image_meta)
        vi = VirtualMachineInstanceConfigInfo(instance,
                                              instance.name, #Vsettan-only
                                              image_info,
                                              datastore,
                                              dc_info,
                                              self._imagecache)
        vm_util.power_off_instance(self._session, instance, vm_ref)

        # Fetch the image if it does not exist in the cache
        self._fetch_image_if_missing(context, vi)

        #Vsettan-only start
        instance_name = vm_util.get_vm_name_for_vcenter(instance)
        template_vm = image_meta.get('properties',{}).get('template_name')

        source_image_path = vi.cache_image_path
        if template_vm:
            template_ref = vm_util.get_vm_ref_from_name(self._session, template_vm)
            template_vmdk = vm_util.get_vmdk_info(self._session, template_ref)
            source_image_path = template_vmdk.path
        #Vsettan-only end

        # Get the rescue disk path
        rescue_disk_path = datastore.build_path(instance.uuid,
                "%s-rescue.%s" % (image_info.image_id, image_info.file_type))

        # Copy the cached image to the be the rescue disk. This will be used
        # as the rescue disk for the instance.
        ds_util.disk_copy(self._session, dc_info.ref,
                          source_image_path, #Vsettan-only
                          rescue_disk_path)
        # Attach the rescue disk to the instance
        self._volumeops.attach_disk_to_vm(vm_ref, instance, vmdk.adapter_type,
                                          vmdk.disk_type, rescue_disk_path)
        # Get the rescue device and configure the boot order to
        # boot from this device
        rescue_device = self._get_rescue_device(instance, vm_ref)
        factory = self._session.vim.client.factory
        boot_spec = vm_util.get_vm_boot_spec(factory, rescue_device)
        # Update the VM with the new boot order and power on
        vm_util.reconfigure_vm(self._session, vm_ref, boot_spec)
        vm_util.power_on_instance(self._session, instance, vm_ref=vm_ref)

    def unrescue(self, instance, power_on=True):
        """Unrescue the specified instance."""

        vm_ref = vm_util.get_vm_ref(self._session, instance)
        # Get the rescue device and detach it from the instance.
        try:
            rescue_device = self._get_rescue_device(instance, vm_ref)
        except exception.NotFound:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE('Unable to access the rescue disk'),
                          instance=instance)
        vm_util.power_off_instance(self._session, instance, vm_ref)
        self._volumeops.detach_disk_from_vm(vm_ref, instance, rescue_device,
                                            destroy_disk=True)
        if power_on:
            vm_util.power_on_instance(self._session, instance, vm_ref=vm_ref)

    def power_off(self, instance):
        """Power off the specified instance.

        :param instance: nova.objects.instance.Instance
        """
        vm_util.power_off_instance(self._session, instance)

    def power_on(self, instance):
        vm_util.power_on_instance(self._session, instance)

    def _update_instance_progress(self, context, instance, step, total_steps):
        """Update instance progress percent to reflect current step number
        """
        # Divide the action's workflow into discrete steps and "bump" the
        # instance's progress field as each step is completed.
        #
        # For a first cut this should be fine, however, for large VM images,
        # the clone disk step begins to dominate the equation. A
        # better approximation would use the percentage of the VM image that
        # has been streamed to the destination host.
        progress = round(float(step) / total_steps * 100)
        instance_uuid = instance.uuid
        LOG.debug("Updating instance '%(instance_uuid)s' progress to"
                  " %(progress)d",
                  {'instance_uuid': instance_uuid, 'progress': progress},
                  instance=instance)
        instance.progress = progress
        instance.save()

    def _resize_vm(self, context, instance, vm_ref, flavor, image_meta):
        """Resizes the VM according to the flavor."""
        client_factory = self._session.vim.client.factory
        extra_specs = self._get_extra_specs(flavor, image_meta)
        metadata = self._get_instance_metadata(context, instance)
        vm_resize_spec = vm_util.get_vm_resize_spec(client_factory,
                                                    int(flavor.vcpus),
                                                    int(flavor.memory_mb),
                                                    extra_specs,
                                                    metadata=metadata)
        vm_util.reconfigure_vm(self._session, vm_ref, vm_resize_spec)

    def _resize_disk(self, instance, vm_ref, vmdk, flavor):
        if (flavor.root_gb > instance.root_gb and
            flavor.root_gb > vmdk.capacity_in_bytes / units.Gi):
            root_disk_in_kb = flavor.root_gb * units.Mi
            ds_ref = vmdk.device.backing.datastore
            dc_info = self.get_datacenter_ref_and_name(ds_ref)
            folder = ds_obj.DatastorePath.parse(vmdk.path).dirname
            datastore = ds_obj.DatastorePath.parse(vmdk.path).datastore
            resized_disk = str(ds_obj.DatastorePath(datastore, folder,
                               'resized.vmdk'))
            ds_util.disk_copy(self._session, dc_info.ref, vmdk.path,
                              str(resized_disk))
            self._extend_virtual_disk(instance, root_disk_in_kb, resized_disk,
                                      dc_info.ref)
            self._volumeops.detach_disk_from_vm(vm_ref, instance, vmdk.device)
            original_disk = str(ds_obj.DatastorePath(datastore, folder,
                                'original.vmdk'))
            ds_util.disk_move(self._session, dc_info.ref, vmdk.path,
                              original_disk)
            ds_util.disk_move(self._session, dc_info.ref, resized_disk,
                              vmdk.path)
            self._volumeops.attach_disk_to_vm(vm_ref, instance,
                                              vmdk.adapter_type,
                                              vmdk.disk_type, vmdk.path)

    def _remove_ephemerals_and_swap(self, vm_ref):
        devices = vm_util.get_ephemerals(self._session, vm_ref)
        swap = vm_util.get_swap(self._session, vm_ref)
        if swap is not None:
            devices.append(swap)

        if devices:
            vm_util.detach_devices_from_vm(self._session, vm_ref, devices)

    def _resize_create_ephemerals_and_swap(self, vm_ref, instance,
                                           block_device_info):
        vmdk = vm_util.get_vmdk_info(self._session, vm_ref,
                                     uuid=instance.uuid)
        ds_ref = vmdk.device.backing.datastore
        datastore = ds_util.get_datastore_by_ref(self._session, ds_ref)
        dc_info = self.get_datacenter_ref_and_name(ds_ref)
        folder = ds_obj.DatastorePath.parse(vmdk.path).dirname
        self._create_ephemeral(block_device_info, instance, vm_ref,
                               dc_info, datastore, folder, vmdk.adapter_type)
        self._create_swap(block_device_info, instance, vm_ref, dc_info,
                          datastore, folder, vmdk.adapter_type)

    # Vsettan-only start hot resize
    def _hot_resize_enabled(self, instance):
        """check if the vm can be hot resized according to the flavors and vm
           configurations. so far memory hot remove is not supported.
        """
        vm_ref = vm_util.get_vm_ref(self._session, instance)
        prop_list = ["config.cpuHotAddEnabled",
                     "config.cpuHotRemoveEnabled",
                     "config.memoryHotAddEnabled",
                     "config.hotPlugMemoryIncrementSize",
                     "config.hotPlugMemoryLimit",
                     "config.version"]
        props = self._session._call_method(vim_util, "get_dynamic_properties",
                                           vm_ref, "VirtualMachine", prop_list)
        resize = {}
        # cpuHotRemoveEnabled is also retrieved, but will not used. Only add
        # cpu is supported.
        resize['cpuHotAdd'] = props.get("config.cpuHotAddEnabled")
        resize['memHotAdd'] = props.get("config.memoryHotAddEnabled")
        resize['mem_incr_size'] = \
            props.get("config.hotPlugMemoryIncrementSize")
        resize['mem_cap'] = props.get("config.hotPlugMemoryLimit")
        # For vmx-10, memory hot add may not work.
        # But we do not refuse to do it.
        hardware_version = props.get("config.version")
        if hardware_version == 'vmx-10':
            LOG.warning(_LW("Hardware version is vmx-10. Memory hot resize "
                            "may not work correctly"))
            # resize['memHotAdd'] = False
        root_disk = self._volumeops.getRootDisk(instance)
        resize['disk_resizable'] = root_disk['is_scsi']
        if not resize['disk_resizable']:
            LOG.warning(_LW("insstance[%s]: root disk can't be resized. Only "
                            "scsi disk can be resized.") % instance.uuid)
        return resize

    def _hot_resize_doable(self, instance, flavor):
        """Check if the driver is hot resize enabled."""
        conf_enabled = CONF.vmware.enable_vm_hot_resize
        if not conf_enabled or not instance or not flavor:
            return False, flavor['memory_mb']

        old_flavor = instance.get_flavor()
        cpu_delta = flavor['vcpus'] - old_flavor['vcpus']
        memory_delta = flavor['memory_mb'] - old_flavor['memory_mb']
        disk_delta = flavor['root_gb'] - old_flavor['root_gb']

        # No change. Needn't resize
        if ((flavor['id'] == old_flavor['id']) or
            (cpu_delta < 0 or memory_delta < 0 or disk_delta < 0) or
            (cpu_delta == 0 and memory_delta == 0 and disk_delta == 0)):
            return False, flavor['memory_mb']

        resize = self._hot_resize_enabled(instance)

        # Check if cpu hot resize doable
        cpu_doable = resize['cpuHotAdd'] and cpu_delta > 0
        cpu_resize = not cpu_delta == 0

        # Check if disk hot resize doable
        disk_doable = resize['disk_resizable'] and disk_delta > 0
        disk_resize = not disk_delta == 0

        # Check if memory hot resize doable
        memory_doable = (resize['memHotAdd'] and memory_delta > 0 and
                         flavor['memory_mb'] <= resize['mem_cap'])
        memory_resize = not memory_delta == 0

        # Calculate new memory size
        new_memory = flavor['memory_mb']
        if (memory_doable and memory_resize and
            CONF.vmware.strict_resize_memory):
            # Abandon memory hot resize, if memory_delta is not multiple
            # of hotPlugMemoryIncrementSize
            if memory_delta % resize['mem_incr_size'] != 0:
                memory_doable = False
        elif (memory_doable and memory_resize and
              not CONF.vmware.strict_resize_memory):
            import math
            # Simply return the memory to the smallest value which is greateri
            # than the value in flavor.
            new_memory = (int(math.ceil(memory_delta * 1.0 /
                              resize['mem_incr_size'])) *
                         resize['mem_incr_size'] + old_flavor['memory_mb'])
            if new_memory > resize['mem_cap']:
                LOG.warning(_LW("Can't resize the memory because new memory "
                                "%(size)s exceeds hotPlugMemoryLimit %(cap)s"),
                                {'size': new_memory, 'cap': resize['mem_cap']})
                memory_doable = False
        not_doable = ((not cpu_doable and cpu_resize) or
                      (not disk_doable and disk_resize) or
                      (not memory_doable and memory_resize))
        return not not_doable, new_memory

    def prepare_hot_resize(self, context, instance, dest, flavor):
        """Nothing need to prepare. Just change the migrate state."""
        self._update_instance_progress(context, instance,
            step=RESIZE_TOTAL_STEPS - 1, total_steps=RESIZE_TOTAL_STEPS)
    # Vsettan-only stop hot resize

    def migrate_disk_and_power_off(self, context, instance, dest,
                                   flavor):
        """Transfers the disk of a running instance in multiple phases, turning
        off the instance before the end.
        """
        vm_ref = vm_util.get_vm_ref(self._session, instance)
        vmdk = vm_util.get_vmdk_info(self._session, vm_ref,
                                     uuid=instance.uuid)

        # Checks if the migration needs a disk resize down.
        if (flavor.root_gb < instance.root_gb or
            (flavor.root_gb != 0 and
             flavor.root_gb < vmdk.capacity_in_bytes / units.Gi)):
            reason = _("Unable to shrink disk.")
            raise exception.InstanceFaultRollback(
                exception.ResizeError(reason=reason))

        # TODO(garyk): treat dest parameter. Migration needs to be treated.

        # 0. Zero out the progress to begin
        self._update_instance_progress(context, instance,
                                       step=0,
                                       total_steps=RESIZE_TOTAL_STEPS)

        # 1. Power off the instance
        vm_util.power_off_instance(self._session, instance, vm_ref)
        self._update_instance_progress(context, instance,
                                       step=1,
                                       total_steps=RESIZE_TOTAL_STEPS)

        # Vsettan-only (prs-related) begin
        # Migrate instance to another host
        src_host = vm_util.get_host_name_for_vm(self._session, instance)
        if dest != CONF.vmware.host_ip and src_host != dest:
            host_ref = self._get_host_ref_from_name(dest)
            res_ref = vm_util.get_pool_refs_by_host(self._session, dest)[0]
            vm_util.disassociate_vmref_from_instance(self._session, instance,
                                                 vm_ref,
                                                 suffix=self._migrate_suffix)
            ds_ref = ds_util.get_datastore(
                            self._session, self._cluster,
                            datastore_regex=self._datastore_regex).ref
            dc_info = self.get_datacenter_ref_and_name(ds_ref)
            vm_util.clone_vmref_for_instance(self._session, instance, vm_ref,
                                         host_ref, ds_ref, dc_info.vmFolder,
                                         res_ref)
            instance_name = vm_util.get_vm_name_for_vcenter(instance)
            vm_ref = vm_util.search_vm_ref_by_identifier(self._session,
                                                         instance_name)
        # Vsettan-only (prs-related) end

        # 2. Reconfigure the VM properties
        self._resize_vm(context, instance, vm_ref, flavor, instance.image_meta)

        self._update_instance_progress(context, instance,
                                       step=2,
                                       total_steps=RESIZE_TOTAL_STEPS)

        # 3.Reconfigure the disk properties
        self._resize_disk(instance, vm_ref, vmdk, flavor)
        self._update_instance_progress(context, instance,
                                       step=3,
                                       total_steps=RESIZE_TOTAL_STEPS)

        # 4. Purge ephemeral and swap disks
        self._remove_ephemerals_and_swap(vm_ref)
        self._update_instance_progress(context, instance,
                                       step=4,
                                       total_steps=RESIZE_TOTAL_STEPS)

    def confirm_migration(self, migration, instance, network_info):
        """Confirms a resize, destroying the source VM."""
        vm_ref = vm_util.get_vm_ref(self._session, instance)
        # Vsettan-only (prs-relaterd) begin
        if migration.source_compute != migration.dest_compute:
            instance_name = vm_util.get_vm_name_for_vcenter(instance)
            vm_ref = vm_util.search_vm_ref_by_identifier(self._session,
                                        instance_name + self._migrate_suffix)
            vm_util.destroy_vm(self._session, instance, vm_ref)
            return
        # Vsettan-only (prs-related) end

        vmdk = vm_util.get_vmdk_info(self._session, vm_ref,
                                     uuid=instance.uuid)
        ds_ref = vmdk.device.backing.datastore
        dc_info = self.get_datacenter_ref_and_name(ds_ref)
        folder = ds_obj.DatastorePath.parse(vmdk.path).dirname
        datastore = ds_obj.DatastorePath.parse(vmdk.path).datastore
        original_disk = ds_obj.DatastorePath(datastore, folder,
                                             'original.vmdk')
        ds_browser = self._get_ds_browser(ds_ref)
        if ds_util.file_exists(self._session, ds_browser,
                               original_disk.parent,
                               original_disk.basename):
            ds_util.disk_delete(self._session, dc_info.ref,
                                str(original_disk))

    def finish_revert_migration(self, context, instance, network_info,
                                block_device_info, power_on=True):
        """Finish reverting a resize."""
        vm_ref = vm_util.get_vm_ref(self._session, instance)
        # Ensure that the VM is off
        vm_util.power_off_instance(self._session, instance, vm_ref)
        client_factory = self._session.vim.client.factory

        # Vsettan-only (prs-related) begin
        instance_name = vm_util.get_vm_name_for_vcenter(instance)
        orig_vm_ref = vm_util.search_vm_ref_by_identifier(self._session,
                                         instance_name + self._migrate_suffix)
        if orig_vm_ref:
            vm_util.destroy_vm(self._session, instance, vm_ref)
            vm_util.associate_vmref_for_instance(self._session, instance,
                                                 suffix=self._migrate_suffix)
            if power_on:
                vm_util.power_on_instance(self._session, instance)
            return
        # Vsettan-only (prs-related) end

        # Reconfigure the VM properties
        extra_specs = self._get_extra_specs(instance.flavor,
                                            instance.image_meta)
        metadata = self._get_instance_metadata(context, instance)
        vm_resize_spec = vm_util.get_vm_resize_spec(client_factory,
                                                    int(instance.vcpus),
                                                    int(instance.memory_mb),
                                                    extra_specs,
                                                    metadata=metadata)
        vm_util.reconfigure_vm(self._session, vm_ref, vm_resize_spec)

        # Reconfigure the disks if necessary
        vmdk = vm_util.get_vmdk_info(self._session, vm_ref,
                                     uuid=instance.uuid)
        ds_ref = vmdk.device.backing.datastore
        dc_info = self.get_datacenter_ref_and_name(ds_ref)
        folder = ds_obj.DatastorePath.parse(vmdk.path).dirname
        datastore = ds_obj.DatastorePath.parse(vmdk.path).datastore
        original_disk = ds_obj.DatastorePath(datastore, folder,
                                             'original.vmdk')
        ds_browser = self._get_ds_browser(ds_ref)
        if ds_util.file_exists(self._session, ds_browser,
                               original_disk.parent,
                               original_disk.basename):
            self._volumeops.detach_disk_from_vm(vm_ref, instance, vmdk.device)
            ds_util.disk_delete(self._session, dc_info.ref, vmdk.path)
            ds_util.disk_move(self._session, dc_info.ref,
                              str(original_disk), vmdk.path)
            self._volumeops.attach_disk_to_vm(vm_ref, instance,
                                              vmdk.adapter_type,
                                              vmdk.disk_type, vmdk.path)
        # Reconfigure ephemerals
        self._remove_ephemerals_and_swap(vm_ref)
        self._resize_create_ephemerals_and_swap(vm_ref, instance,
                                                block_device_info)
        if power_on:
            vm_util.power_on_instance(self._session, instance)

    # Vsettan-only start hot resize
    def finish_hot_resize(self, context, migration, instance, disk_info,
                          network_info, image_meta,
                          block_device_info=None):
        """Completes a hot resize."""
        vm_ref = vm_util.get_vm_ref(self._session, instance)
        client_factory = self._session.vim.client.factory
        flavor = instance.flavor
        extra_specs = self._get_extra_specs(flavor)
        vm_resize_spec = vm_util.get_vm_resize_spec(client_factory,
                                                    int(flavor['vcpus']),
                                                    int(flavor['memory_mb']),
                                                    extra_specs)
        vm_util.reconfigure_vm(self._session, vm_ref, vm_resize_spec)
        # Resize the disk (if larger)
        old_root_gb = instance.old_flavor.root_gb
        if instance.root_gb > int(old_root_gb):
            root_disk_in_kb = instance.root_gb * units.Mi
            root_disk = self._volumeops.getRootDisk(instance)
            virtual_disk = root_disk['device']
            virtual_disk.capacityInKB = root_disk_in_kb
            disk_resize_spec = vm_util.get_disk_resize_spec(client_factory,
                                                            virtual_disk)

            disk_resize_task = self._session._call_method(
                                        self._session.vim,
                                        "ReconfigVM_Task", vm_ref,
                                        spec=disk_resize_spec)
            self._session._wait_for_task(disk_resize_task)
        self._update_instance_progress(context, instance,
                                       step=RESIZE_TOTAL_STEPS,
                                       total_steps=RESIZE_TOTAL_STEPS)
    # Vsettan-only stop hot resize

    def finish_migration(self, context, migration, instance, disk_info,
                         network_info, image_meta, resize_instance=False,
                         block_device_info=None, power_on=True):
        """Completes a resize, turning on the migrated instance."""
        # Vsettan-only (prs-related) begin
        # Remove original VM from cache
        vm_util.vm_ref_cache_delete(instance['uuid'])
        # Vsettan-only (prs-related) end
        vm_ref = vm_util.get_vm_ref(self._session, instance)

        # 5. Update ephemerals if necessary
        self._resize_create_ephemerals_and_swap(vm_ref, instance,
                                                block_device_info)

        self._update_instance_progress(context, instance,
                                       step=5,
                                       total_steps=RESIZE_TOTAL_STEPS)
        # 6. Start VM
        if power_on:
            vm_util.power_on_instance(self._session, instance, vm_ref=vm_ref)

        self._update_instance_progress(context, instance,
                                       step=6,
                                       total_steps=RESIZE_TOTAL_STEPS)

    def live_migration(self, context, instance_ref, dest,
                       post_method, recover_method, block_migration=False):
        """Spawning live_migration operation for distributing high-load."""
        vm_ref = vm_util.get_vm_ref(self._session, instance_ref)

        host_ref = self._get_host_ref_from_name(dest)
        root_res_pool = None # Vsettan-only (prs-related)
        if host_ref is None:
            # Vsettan-only (prs-related) begin
            # Get root resource pool for destination cluster
            dest_cls = []
            dest_cls.append(dest)
            dict_mors = vm_util.get_all_cluster_refs_by_name(self._session,
                                                             dest_cls)
            for node in dict_mors.keys():
                if dict_mors.get(node)['name'] == dest:
                    root_res_pool = dict_mors.get(node)['res_pool_mor']
                    break
            if root_res_pool is None:
                raise exception.HostNotFound(host=dest)
            else:
                LOG.debug("Cluster resource pool %s is found for destination",
                          root_res_pool)
        else:
           # Get root resource pool of target host
           results = vm_util.get_pool_refs_by_host(self._session, dest)
           root_res_pool = results[0]
           # Vsettan-only (prs-related) end

        LOG.debug("Migrating VM to host %s", dest, instance=instance_ref)
        try:
            vm_migrate_task = self._session._call_method(
                                    self._session.vim,
                                    "MigrateVM_Task", vm_ref,
                                    pool=root_res_pool, # Vsettan-only (prs-related)
                                    host=host_ref,
                                    priority="defaultPriority")
            self._session._wait_for_task(vm_migrate_task)
        except Exception:
            with excutils.save_and_reraise_exception():
                recover_method(context, instance_ref, dest, block_migration)
        post_method(context, instance_ref, dest, block_migration)
        LOG.debug("Migrated VM to host %s", dest, instance=instance_ref)

    def poll_rebooting_instances(self, timeout, instances):
        """Poll for rebooting instances."""
        ctxt = nova_context.get_admin_context()

        instances_info = dict(instance_count=len(instances),
                timeout=timeout)

        if instances_info["instance_count"] > 0:
            LOG.info(_LI("Found %(instance_count)d hung reboots "
                         "older than %(timeout)d seconds"), instances_info)

        for instance in instances:
            LOG.info(_LI("Automatically hard rebooting"), instance=instance)
            self.compute_api.reboot(ctxt, instance, "HARD")

    def get_info(self, instance):
        """Return data about the VM instance."""
        vm_ref = vm_util.get_vm_ref(self._session, instance)

        lst_properties = ["summary.config.numCpu",
                    "summary.config.memorySizeMB",
                    "runtime.powerState"]
        vm_props = self._session._call_method(vim_util,
                    "get_object_properties", None, vm_ref, "VirtualMachine",
                    lst_properties)
        query = vm_util.get_values_from_object_properties(
                self._session, vm_props)
        max_mem = int(query.get('summary.config.memorySizeMB', 0)) * 1024
        num_cpu = int(query.get('summary.config.numCpu', 0))
        return hardware.InstanceInfo(
            state=VMWARE_POWER_STATES[query['runtime.powerState']],
            max_mem_kb=max_mem,
            mem_kb=max_mem,
            num_cpu=num_cpu)

    # Vsettan-only begin init power state
    def get_all_power_state(self):
        """Return power state of all the VM instances."""
        lst_properties = ["name", "runtime.powerState"]
        results = self._session._call_method(vim_util, "get_objects",
                                             "VirtualMachine", lst_properties)
        power_states = {}
        while results:
            token = vm_util._get_token(results)
            for obj in results.objects:
                # VM name may have display name as its prefix, uuid is the
                # last 36 characters.
                uuid = obj.propSet[0].val[-36:]
                state = obj.propSet[1].val
                power_states[uuid] = VMWARE_POWER_STATES[state]
            if token:
                results = self._session._call_method(vim_util,
                              "continue_to_get_objects", token)
            else:
                return power_states
    # Vsettan-only stop init power state

    def _get_diagnostics(self, instance):
        """Return data about VM diagnostics."""
        vm_ref = vm_util.get_vm_ref(self._session, instance)
        lst_properties = ["summary.config",
                          "summary.quickStats",
                          "summary.runtime"]
        vm_props = self._session._call_method(vim_util,
                    "get_object_properties", None, vm_ref, "VirtualMachine",
                    lst_properties)
        query = vm_util.get_values_from_object_properties(self._session,
                                                          vm_props)
        data = {}
        # All of values received are objects. Convert them to dictionaries
        for value in query.values():
            prop_dict = vim_util.object_to_dict(value, list_depth=1)
            data.update(prop_dict)
        return data

    def get_diagnostics(self, instance):
        """Return data about VM diagnostics."""
        data = self._get_diagnostics(instance)
        # Add a namespace to all of the diagnostsics
        return {'vmware:' + k: v for k, v in data.items()}

    def get_instance_diagnostics(self, instance):
        """Return data about VM diagnostics."""
        data = self._get_diagnostics(instance)
        state = data.get('powerState')
        if state:
            state = power_state.STATE_MAP[VMWARE_POWER_STATES[state]]
        uptime = data.get('uptimeSeconds', 0)
        config_drive = configdrive.required_by(instance)
        diags = diagnostics.Diagnostics(state=state,
                                        driver='vcmvmwareapi',
                                        config_drive=config_drive,
                                        hypervisor_os='esxi',
                                        uptime=uptime)
        diags.memory_details.maximum = data.get('memorySizeMB', 0)
        diags.memory_details.used = data.get('guestMemoryUsage', 0)
        # TODO(garyk): add in cpu, nic and disk stats
        return diags

    def _get_vnc_console_connection(self, instance):
        """Return connection info for a vnc console."""
        vm_ref = vm_util.get_vm_ref(self._session, instance)
        opt_value = self._session._call_method(vim_util,
                               'get_dynamic_property',
                               vm_ref, 'VirtualMachine',
                               vm_util.VNC_CONFIG_KEY)
        if opt_value:
            port = int(opt_value.value)
        else:
            raise exception.ConsoleTypeUnavailable(console_type='vnc')

        return {'port': port,
                'internal_access_path': None}

    @staticmethod
    def _get_machine_id_str(network_info):
        machine_id_str = ''
        for vif in network_info:
            # TODO(vish): add support for dns2
            # TODO(sateesh): add support for injection of ipv6 configuration
            network = vif['network']
            ip_v4 = netmask_v4 = gateway_v4 = broadcast_v4 = dns = None
            subnets_v4 = [s for s in network['subnets'] if s['version'] == 4]
            if len(subnets_v4) > 0:
                if len(subnets_v4[0]['ips']) > 0:
                    ip_v4 = subnets_v4[0]['ips'][0]
                if len(subnets_v4[0]['dns']) > 0:
                    dns = subnets_v4[0]['dns'][0]['address']

                netmask_v4 = str(subnets_v4[0].as_netaddr().netmask)
                gateway_v4 = subnets_v4[0]['gateway']['address']
                broadcast_v4 = str(subnets_v4[0].as_netaddr().broadcast)

            interface_str = ";".join([vif['address'],
                                      ip_v4 and ip_v4['address'] or '',
                                      netmask_v4 or '',
                                      gateway_v4 or '',
                                      broadcast_v4 or '',
                                      dns or ''])
            machine_id_str = machine_id_str + interface_str + '#'
        return machine_id_str

    def _set_machine_id(self, client_factory, instance, network_info,
                        vm_ref=None):
        """Set the machine id of the VM for guest tools to pick up
        and reconfigure the network interfaces.
        """
        if vm_ref is None:
            vm_ref = vm_util.get_vm_ref(self._session, instance)

        machine_id_change_spec = vm_util.get_machine_id_change_spec(
                                 client_factory,
                                 self._get_machine_id_str(network_info))

        LOG.debug("Reconfiguring VM instance to set the machine id",
                  instance=instance)
        vm_util.reconfigure_vm(self._session, vm_ref, machine_id_change_spec)
        LOG.debug("Reconfigured VM instance to set the machine id",
                  instance=instance)

    @utils.synchronized('vmware.get_and_set_vnc_port')
    def _get_and_set_vnc_config(self, client_factory, instance, vm_ref):
        """Set the vnc configuration of the VM."""
        port = vm_util.get_vnc_port(self._session)
        vnc_config_spec = vm_util.get_vnc_config_spec(
                                      client_factory, port)

        LOG.debug("Reconfiguring VM instance to enable vnc on "
                  "port - %(port)s", {'port': port},
                  instance=instance)
        vm_util.reconfigure_vm(self._session, vm_ref, vnc_config_spec)
        LOG.debug("Reconfigured VM instance to enable vnc on "
                  "port - %(port)s", {'port': port},
                  instance=instance)

    def _get_ds_browser(self, ds_ref):
        ds_browser = self._datastore_browser_mapping.get(ds_ref.value)
        if not ds_browser:
            ds_browser = self._session._call_method(
                vim_util, "get_dynamic_property", ds_ref, "Datastore",
                "browser")
            self._datastore_browser_mapping[ds_ref.value] = ds_browser
        return ds_browser

    def _get_host_ref_from_name(self, host_name):
        """Get reference to the host with the name specified."""
        host_objs = self._session._call_method(vim_util, "get_objects",
                    "HostSystem", ["name"])
        vm_util._cancel_retrieve_if_necessary(self._session, host_objs)
        for host in host_objs:
            if hasattr(host, 'propSet'):
                if host.propSet[0].val == host_name:
                    return host.obj
        return None
        ### Vsettan-only (prs-related)begin
        ### Get objects arrry from host_objs
        ##return vm_util._get_object_from_results(self._session, host_objs,
        ##                                        host_name,
        ##                                        vm_util._get_object_for_value)
        ### Vsettan-only (prs_related) end

    def _create_folder_if_missing(self, ds_name, ds_ref, folder):
        """Create a folder if it does not exist.

        Currently there are two folder that are required on the datastore
         - base folder - the folder to store cached images
         - temp folder - the folder used for snapshot management and
                         image uploading
        This method is aimed to be used for the management of those
        folders to ensure that they are created if they are missing.
        The ds_util method mkdir will be used to check if the folder
        exists. If this throws and exception 'FileAlreadyExistsException'
        then the folder already exists on the datastore.
        """
        path = ds_obj.DatastorePath(ds_name, folder)
        dc_info = self.get_datacenter_ref_and_name(ds_ref)
        try:
            ds_util.mkdir(self._session, path, dc_info.ref)
            LOG.debug("Folder %s created.", path)
        except vexc.FileAlreadyExistsException:
            # NOTE(hartsocks): if the folder already exists, that
            # just means the folder was prepped by another process.
            pass

    def check_cache_folder(self, ds_name, ds_ref):
        """Check that the cache folder exists."""
        self._create_folder_if_missing(ds_name, ds_ref, self._base_folder)

    def check_temp_folder(self, ds_name, ds_ref):
        """Check that the temp folder exists."""
        self._create_folder_if_missing(ds_name, ds_ref, self._tmp_folder)

    def inject_network_info(self, instance, network_info):
        """inject network info for specified instance."""
        # Set the machine.id parameter of the instance to inject
        # the NIC configuration inside the VM
        client_factory = self._session.vim.client.factory
        self._set_machine_id(client_factory, instance, network_info)

    def manage_image_cache(self, context, instances):
        if not CONF.remove_unused_base_images:
            LOG.debug("Image aging disabled. Aging will not be done.")
            return

        datastores = ds_util.get_available_datastores(self._session,
                                                      self._cluster,
                                                      self._host, # Vsettan-only
                                                      self._datastore_regex,
                                                      self._storage_pod) # Vsettan-only
        datastores_info = []
        for ds in datastores:
            dc_info = self.get_datacenter_ref_and_name(ds.ref)
            datastores_info.append((ds, dc_info))
        self._imagecache.update(context, instances, datastores_info)

    def _get_valid_vms_from_retrieve_result(self, retrieve_result):
        """Returns list of valid vms from RetrieveResult object."""
        lst_vm_names = []

        while retrieve_result:
            for vm in retrieve_result.objects:
                vm_uuid = None
                conn_state = None
                for prop in vm.propSet:
                    if prop.name == "runtime.connectionState":
                        conn_state = prop.val
                    elif prop.name == 'config.extraConfig["nvp.vm-uuid"]':
                        vm_uuid = prop.val.value
                # Ignore VM's that do not have nvp.vm-uuid defined
                if not vm_uuid:
                    continue
                # Ignoring the orphaned or inaccessible VMs
                if conn_state not in ["orphaned", "inaccessible"]:
                    lst_vm_names.append(vm_uuid)
            retrieve_result = self._session._call_method(vutil,
                                                         'continue_retrieval',
                                                         retrieve_result)
        return lst_vm_names

    def instance_exists(self, instance):
        try:
            vm_util.get_vm_ref(self._session, instance)
            return True
        except exception.InstanceNotFound:
            return False

    def attach_interface(self, instance, image_meta, vif):
        """Attach an interface to the instance."""
        vif_model = image_meta.properties.get('hw_vif_model',
                                              constants.DEFAULT_VIF_MODEL)
        vif_model = vm_util.convert_vif_model(vif_model)
        vif_info = vmwarevif.get_vif_dict(self._session, self._cluster,
                                          vif_model, utils.is_neutron(), vif)
        vm_ref = vm_util.get_vm_ref(self._session, instance)
        # Ensure that there is not a race with the port index management
        with lockutils.lock(instance.uuid,
                            lock_file_prefix='nova-vmware-hot-plug'):
            port_index = vm_util.get_attach_port_index(self._session, vm_ref)
            client_factory = self._session.vim.client.factory
            attach_config_spec = vm_util.get_network_attach_config_spec(
                                        client_factory, vif_info, port_index)
            LOG.debug("Reconfiguring VM to attach interface",
                      instance=instance)
            try:
                vm_util.reconfigure_vm(self._session, vm_ref,
                                       attach_config_spec)
            except Exception as e:
                LOG.error(_LE('Attaching network adapter failed. Exception: '
                              '%s'),
                          e, instance=instance)
                raise exception.InterfaceAttachFailed(
                        instance_uuid=instance.uuid)

            context = nova_context.get_admin_context()
            self._network_api.update_instance_vnic_index(
                context, instance, vif, port_index)

        LOG.debug("Reconfigured VM to attach interface", instance=instance)

    def detach_interface(self, instance, vif):
        """Detach an interface from the instance."""
        vm_ref = vm_util.get_vm_ref(self._session, instance)
        # Ensure that there is not a race with the port index management
        with lockutils.lock(instance.uuid,
                            lock_file_prefix='nova-vmware-hot-plug'):
            port_index = vm_util.get_vm_detach_port_index(self._session,
                                                          vm_ref,
                                                          vif['id'])
            if port_index is None:
                msg = _("No device with interface-id %s exists on "
                        "VM") % vif['id']
                raise exception.NotFound(msg)

            hardware_devices = self._session._call_method(vim_util,
                            "get_dynamic_property", vm_ref,
                            "VirtualMachine", "config.hardware.device")
            device = vmwarevif.get_network_device(hardware_devices,
                                                  vif['address'])
            if device is None:
                msg = _("No device with MAC address %s exists on the "
                        "VM") % vif['address']
                raise exception.NotFound(msg)

            context = nova_context.get_admin_context()
            self._network_api.update_instance_vnic_index(
                context, instance, vif, None)

            client_factory = self._session.vim.client.factory
            detach_config_spec = vm_util.get_network_detach_config_spec(
                                        client_factory, device, port_index)
            LOG.debug("Reconfiguring VM to detach interface",
                      instance=instance)
            try:
                vm_util.reconfigure_vm(self._session, vm_ref,
                                       detach_config_spec)
            except Exception as e:
                LOG.error(_LE('Detaching network adapter failed. Exception: '
                              '%s'),
                          e, instance=instance)
                raise exception.InterfaceDetachFailed(
                        instance_uuid=instance.uuid)
        LOG.debug("Reconfigured VM to detach interface", instance=instance)

    # Vsettan-only start live snapshot
    def list_instance_snapshots(self, context, instance):
        """get all the snapshots of the specified VM instance."""
        LOG.debug("Getting Snapshots of the VM instance", instance=instance)
        vm_ref = vm_util.get_vm_ref(self._session, instance)

        snapshots = self._get_vm_snapshots(vm_ref)
        LOG.debug("Got Snapshots of the VM instance", instance=instance)
        return snapshots

    def _get_vm_snapshots(self, vm_ref):
        # Get snapshots of the VM
        snapshot_dict = vm_util.get_snapshots_from_vm_ref(self._session,
                                                          vm_ref)
        return snapshot_dict.values()

    def create_instance_snapshot(self, context, instance, **kwargs):
        """Create the snapshot of the specified VM instance."""
        LOG.debug("Creating Snapshot of the VM instance", instance=instance)
        vm_ref = vm_util.get_vm_ref(self._session, instance)
        snapshot_name = kwargs.get('snapshot_name')
        desc = kwargs.get('description')
        metadata = kwargs.get('metadata')
        if 'memory' in metadata:
            memory = metadata.get('memory')
        else:
            memory = False
        if 'quiesce' in metadata:
            quiesce = metadata.get('quiesce')
        else:
            quiesce = True
        snapshot_task = self._session._call_method(self._session.vim,
                                                   "CreateSnapshot_Task",
                                                   vm_ref,
                                                   name=snapshot_name,
                                                   description=desc,
                                                   memory=memory,
                                                   quiesce=quiesce)
        self._session._wait_for_task(snapshot_task)
        LOG.debug("Created Snapshot of the VM instance", instance=instance)
        task_info = self._session._call_method(vim_util,
                                               "get_dynamic_property",
                                               snapshot_task, "Task", "info")
        snapshot_ref = task_info.result
        return vm_util.get_snapshot_obj_by_snapshot_ref(self._session, vm_ref,
                                                        snapshot_ref)

    def delete_instance_snapshot(self, context, instance,
                                 snapshot_id):
        """Delete snapshot of the instance."""
        LOG.debug("Deleting snapshot %s of instance", snapshot_id,
                  instance=instance)
        vm_ref = vm_util.get_vm_ref(self._session, instance)
        snapshot_ref = vm_util.get_snapshot_ref_by_snapshot_id(self._session,
                                                               vm_ref,
                                                               snapshot_id)
        snapshot_task = self._session._call_method(self._session.vim,
                                                   "RemoveSnapshot_Task",
                                                   snapshot_ref,
                                                   removeChildren=False)
        self._session._wait_for_task(snapshot_task)
        LOG.debug("Deleted Snapshot of the VM instance", instance=instance)

    def restore_instance_snapshot(self, context, instance,
                                 snapshot_id=None):
        """Restore snapshot of the instance."""
        LOG.debug("Restore to a snapshot of instance", instance=instance)
        vm_ref = vm_util.get_vm_ref(self._session, instance)
        if snapshot_id is not None:
            snapshot_ref = vm_util.get_snapshot_ref_by_snapshot_id(
                self._session, vm_ref, snapshot_id)
            snapshot_task = self._session._call_method(
                self._session.vim, "RevertToSnapshot_Task",
                snapshot_ref)
        else:
            current_sp_id = vm_util.get_current_snapshot_from_vm_ref(
                self._session, vm_ref)
            if current_sp_id is None:
                raise exception.NotFound(_("This virtual machine does not have"
                                           " a current snapshot."))
            else:
                snapshot_task = self._session._call_method(
                    self._session.vim, "RevertToCurrentSnapshot_Task",
                    vm_ref)
        self._session._wait_for_task(snapshot_task)
        LOG.debug("Restored the snapshot of the VM instance",
                  instance=instance)
    # Vsettan-only stop live snapshot

    def _use_disk_image_as_full_clone(self, vm_ref, vi):
        """Uses cached image disk by copying it into the VM directory."""

        instance_folder = vi.instance_name #Vsettan-only
        root_disk_name = "%s.vmdk" % vi.instance_name #Vsettan-only
        root_disk_ds_loc = vi.datastore.build_path(instance_folder,
                                                   root_disk_name)

        vm_util.copy_virtual_disk(
                self._session,
                vi.dc_info.ref,
                str(vi.cache_image_path),
                str(root_disk_ds_loc))

        self._extend_if_required(
                vi.dc_info, vi.ii, vi.instance, str(root_disk_ds_loc))

        self._volumeops.attach_disk_to_vm(
                vm_ref, vi.instance,
                vi.ii.adapter_type, vi.ii.disk_type,
                str(root_disk_ds_loc),
                vi.root_gb * units.Mi, False,
                disk_io_limits=vi._extra_specs.disk_io_limits)

    def _sized_image_exists(self, sized_disk_ds_loc, ds_ref):
        ds_browser = self._get_ds_browser(ds_ref)
        return ds_util.file_exists(
                self._session, ds_browser, sized_disk_ds_loc.parent,
                sized_disk_ds_loc.basename)

    def _use_disk_image_as_linked_clone(self, vm_ref, vi):
        """Uses cached image as parent of a COW child in the VM directory."""

        sized_image_disk_name = "%s.vmdk" % vi.ii.image_id
        if vi.root_gb > 0:
            sized_image_disk_name = "%s.%s.vmdk" % (vi.ii.image_id, vi.root_gb)
        sized_disk_ds_loc = vi.cache_image_folder.join(sized_image_disk_name)

        # Ensure only a single thread extends the image at once.
        # We do this by taking a lock on the name of the extended
        # image. This allows multiple threads to create resized
        # copies simultaneously, as long as they are different
        # sizes. Threads attempting to create the same resized copy
        # will be serialized, with only the first actually creating
        # the copy.
        #
        # Note that the object is in a per-nova cache directory,
        # so inter-nova locking is not a concern. Consequently we
        # can safely use simple thread locks.

        with lockutils.lock(str(sized_disk_ds_loc),
                            lock_file_prefix='nova-vmware-image'):

            if not self._sized_image_exists(sized_disk_ds_loc,
                                            vi.datastore.ref):
                LOG.debug("Copying root disk of size %sGb", vi.root_gb,
                          instance=vi.instance)
                try:
                    vm_util.copy_virtual_disk(
                            self._session,
                            vi.dc_info.ref,
                            str(vi.cache_image_path),
                            str(sized_disk_ds_loc))
                except Exception as e:
                    LOG.warning(_LW("Root disk file creation "
                                    "failed - %s"), e)
                    with excutils.save_and_reraise_exception():
                        LOG.error(_LE('Failed to copy cached '
                                      'image %(source)s to '
                                      '%(dest)s for resize: '
                                      '%(error)s'),
                                  {'source': vi.cache_image_path,
                                   'dest': sized_disk_ds_loc,
                                   'error': e})
                        try:
                            ds_util.file_delete(self._session,
                                                sized_disk_ds_loc,
                                                vi.dc_info.ref)
                        except vexc.FileNotFoundException:
                            # File was never created: cleanup not
                            # required
                            pass

                # Resize the copy to the appropriate size. No need
                # for cleanup up here, as _extend_virtual_disk
                # already does it
                self._extend_if_required(
                        vi.dc_info, vi.ii, vi.instance, str(sized_disk_ds_loc))

        # Associate the sized image disk to the VM by attaching to the VM a
        # COW child of said disk.
        self._volumeops.attach_disk_to_vm(
                vm_ref, vi.instance,
                vi.ii.adapter_type, vi.ii.disk_type,
                str(sized_disk_ds_loc),
                vi.root_gb * units.Mi, vi.ii.linked_clone,
                disk_io_limits=vi._extra_specs.disk_io_limits)

    def _use_iso_image(self, vm_ref, vi):
        """Uses cached image as a bootable virtual cdrom."""

        self._attach_cdrom_to_vm(
                vm_ref, vi.instance, vi.datastore.ref,
                str(vi.cache_image_path))

        # Optionally create and attach blank disk
        if vi.root_gb > 0:
            instance_folder = vi.instance_name #Vsettan-only
            root_disk_name = "%s.vmdk" % vi.instance_name #Vsettan-only
            root_disk_ds_loc = vi.datastore.build_path(instance_folder,
                                                       root_disk_name)

            # It is pointless to COW a blank disk
            linked_clone = False

            vm_util.create_virtual_disk(
                    self._session, vi.dc_info.ref,
                    vi.ii.adapter_type,
                    vi.ii.disk_type,
                    str(root_disk_ds_loc),
                    vi.root_gb * units.Mi)

            self._volumeops.attach_disk_to_vm(
                    vm_ref, vi.instance,
                    vi.ii.adapter_type, vi.ii.disk_type,
                    str(root_disk_ds_loc),
                    vi.root_gb * units.Mi, linked_clone,
                    disk_io_limits=vi._extra_specs.disk_io_limits)

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

    def list_instances(self):
        """Lists the VM instances that are registered with vCenter cluster."""
        properties = ['runtime.connectionState',
                      'config.extraConfig["nvp.vm-uuid"]']
        # Vsettan-only start
        if self._res_pool:
            vms = self._session._call_method(
                vim_util, 'get_inner_objects', self._res_pool, 'vm',
                'VirtualMachine', properties)
            lst_vm_names = self._get_valid_vms_from_retrieve_result(vms)
            new_vm_names = []
            for name in lst_vm_names:
                new_vm_names.append(name[-36:])
            return new_vm_names
        # Vsettan-only end
        LOG.debug("Getting list of instances from cluster %s",
                  self._cluster)
        vms = []
        if self._root_resource_pool:
            vms = self._session._call_method(
                vim_util, 'get_inner_objects', self._root_resource_pool, 'vm',
                'VirtualMachine', properties)
        lst_vm_names = self._get_valid_vms_from_retrieve_result(vms)
        # Vsettan-only start
        new_vm_names = []
        for name in lst_vm_names:
            new_vm_names.append(name[-36:])
        # Vsettan-only end
        LOG.debug("Got total of %s instances", str(len(lst_vm_names)))
        return new_vm_names #Vsettan-only

    def get_vnc_console(self, instance):
        """Return connection info for a vnc console using vCenter logic."""

        # vCenter does not run virtual machines and does not run
        # a VNC proxy. Instead, you need to tell OpenStack to talk
        # directly to the ESX host running the VM you are attempting
        # to connect to via VNC.

        vnc_console = self._get_vnc_console_connection(instance)
        host_name = vm_util.get_host_name_for_vm(
                        self._session,
                        instance)
        vnc_console['host'] = host_name

        # NOTE: VM can move hosts in some situations. Debug for admins.
        LOG.debug("VM %(uuid)s is currently on host %(host_name)s",
                  {'uuid': instance.uuid, 'host_name': host_name},
                  instance=instance)
        return ctype.ConsoleVNC(**vnc_console)

    def get_mks_console(self, instance):
        vm_ref = vm_util.get_vm_ref(self._session, instance)
        ticket = self._session._call_method(self._session.vim,
                                            'AcquireTicket',
                                            vm_ref,
                                            ticketType='mks')
        thumbprint = ticket.sslThumbprint.replace(':', '').lower()
        mks_auth = {'ticket': ticket.ticket,
                    'cfgFile': ticket.cfgFile,
                    'thumbprint': thumbprint}
        internal_access_path = jsonutils.dumps(mks_auth)
        return ctype.ConsoleMKS(ticket.host, ticket.port, internal_access_path)

    # Vsettan-only begin
    def _download_file(self, dc_name, log_path):
        session_vim = self._session.vim
        cookies = session_vim.client.options.transport.cookiejar
        fd = read_write_util.VMwareHTTPReadFile(self._session._host,
                                                dc_name,
                                                log_path.datastore,
                                                cookies,
                                                log_path.rel_path)
        tf = tempfile.TemporaryFile()
        while True:
            buff = fd.read()
            if not buff:
                break
            tf.write(buff)
        return tf

    def get_console_output(self, instance):
        vm_ref = vm_util.get_vm_ref(self._session, instance)
        vm_info = self._session._call_method(vim_util, "get_dynamic_property",
                vm_ref, "VirtualMachine", "config.files")
        log_path_str = vm_info.logDirectory + 'console.log'
        log_path = ds_obj.DatastorePath.parse(log_path_str)

        # TODO(rgerganov) is there a more efficient way to get dc_name ?
        folder_ref = self._session._call_method(vim_util,
                "get_dynamic_property", vm_ref, "VirtualMachine", "parent")
        dc_ref = self._session._call_method(vim_util, "get_dynamic_property",
                folder_ref, "Folder", "parent")
        dc_name = self._session._call_method(vim_util, "get_dynamic_property",
                dc_ref, "Datacenter", "name")
        try:
            with self._download_file(dc_name, log_path) as fd:
                log_data, remaining = utils.last_bytes(fd, MAX_CONSOLE_BYTES)
                if remaining > 0:
                    LOG.info(_LI('Truncated console log returned, %d bytes '
                             'ignored'), remaining, instance=instance)
                return log_data
        except urllib2.HTTPError as e:
            LOG.error(_LE('Error getting console output: %s'),
                      e, instance=instance)

    def retrieve_instances(self):
        """Retrieves properties for syncing from the VM instances that are registered with the ESX host in the target cluster or resource pool."""
        LOG.debug(_("Getting list of managed instances"))

        lst_properties = ["name",
                "config.instanceUuid",
                'config.extraConfig["nvp.vm-uuid"]',
                "summary.config.numCpu",
                "summary.config.memorySizeMB",
                "runtime.powerState",
                "recentTask",
                "config.files.vmPathName",
                "guest.net"]

        if self._res_pool is not None:
            vm_props = self._session._call_method(vim_util,
                    "get_objects_from_resource_pool", "VirtualMachine", self._res_pool, lst_properties)
        else:
            vm_props = self._session._call_method(vim_util,
                        "get_objects_from_cluster", "VirtualMachine", self._cluster, lst_properties)

        raw_instances = self._get_properties_from_objects(vm_props, lst_properties)
        instances = []
        for raw_instance in raw_instances:
            uuid = raw_instance['config.instanceUuid'] if 'config.instanceUuid' in raw_instance else None
            if 'config.extraConfig["nvp.vm-uuid"]' in raw_instance:
                uuid = raw_instance['config.extraConfig["nvp.vm-uuid"]'].value

            if uuid is None:
                continue

            max_mem = int(raw_instance.get('summary.config.memorySizeMB', 0)) * 1024
            vmPathName = raw_instance['config.files.vmPathName']
            vmFolder = vmPathName[:vmPathName.rfind("/")]

            running_tasks = []
            if len(raw_instance['recentTask']) > 0:
                LOG.debug("recentTask contains items: " + str(raw_instance['recentTask']))
                for task_ref in raw_instance['recentTask'].ManagedObjectReference:
                    task_info = self._session._call_method(vim_util,
                                        'get_dynamic_property',
                                        task_ref,
                                        'Task',
                                        'info')
                    LOG.debug("Retrieved TaskInfo: " + str(task_info))
                    if task_info.state == 'running' or task_info.state == 'queued':
                        running_tasks += [task_info]


            instances += [{'name': raw_instance['name'],
                    'uuid': uuid,
                    'vm_state': VMWARE_VM_STATES[raw_instance['runtime.powerState']],
                    'power_state': VMWARE_POWER_STATES[raw_instance['runtime.powerState']],
                    'max_mem': max_mem,
                    'mem': max_mem,
                    'memory_mb': raw_instance.get('summary.config.memorySizeMB', 0),
                    'vcpus': int(raw_instance.get('summary.config.numCpu', 0)),
                    'runningTasks': running_tasks,
                    'vmFolder': vmFolder,
                    'node': self._nodename,
                    'net':raw_instance['guest.net']}]

        return instances

    def retrieve_instances(self, resource_pools, clusters):
        """Retrieves properties for syncing from the VM instances that are registered with the ESX host in the target cluster or resource pool."""
        LOG.debug(_("Getting list of managed instances"))

        lst_properties = ["name",
                "config.instanceUuid",
                'config.extraConfig["nvp.vm-uuid"]',
                "summary.config.numCpu",
                "summary.config.memorySizeMB",
                "runtime.powerState",
                "recentTask",
                "config.files.vmPathName",
                "guest.net"]
        raw_instances = []
        for res_pool_key in resource_pools.keys():
            res_pool = resource_pools.get(res_pool_key)
            vm_props_from_resource_pool = self._session._call_method(vim_util,
                    "get_objects_from_resource_pool", "VirtualMachine", res_pool, lst_properties)
            raw_instances += self._get_properties_from_objects(vm_props_from_resource_pool, lst_properties)

        for cluster_key in clusters.keys():
            cluster = clusters.get(cluster_key)
            vm_props_from_clusters = self._session._call_method(vim_util,
                        "get_objects_from_cluster", "VirtualMachine", cluster, lst_properties)
            raw_instances += self._get_properties_from_objects(vm_props_from_clusters, lst_properties)

        instances_exist = []
        instances = []
        for raw_instance in raw_instances:
            uuid = raw_instance['config.instanceUuid'] if 'config.instanceUuid' in raw_instance else None
#            comment out the following lines according to issue 195248
#            1. boot A from openstack
#            2  clone B from A via vcenter, nvp.vm-uuid of B is A' uuid,
#            3  B will not be added to openstack by discovery service.
#            so here we need use the instanceuuid directly.

#            if 'config.extraConfig["nvp.vm-uuid"]' in raw_instance:
#                uuid = raw_instance['config.extraConfig["nvp.vm-uuid"]'].value

            if uuid is None:
                continue

            max_mem = int(raw_instance.get('summary.config.memorySizeMB', 0)) * 1024
            vmPathName = raw_instance['config.files.vmPathName']
            vmFolder = vmPathName[:vmPathName.rfind("/")]

            running_tasks = []
            if len(raw_instance['recentTask']) > 0:
                LOG.debug("recentTask contains items: " + str(raw_instance['recentTask']))
                for task_ref in raw_instance['recentTask'].ManagedObjectReference:
                    task_info = self._session._call_method(vim_util,
                                        'get_dynamic_property',
                                        task_ref,
                                        'Task',
                                        'info')
                    LOG.debug("Retrieved TaskInfo: " + str(task_info))
                    if task_info.state == 'running' or task_info.state == 'queued':
                        running_tasks += [task_info]

            if not uuid in instances_exist:
                instances_exist.append(uuid)
                instances += [{'name': raw_instance['name'],
                        'uuid': uuid,
                        'vm_state': VMWARE_VM_STATES[raw_instance['runtime.powerState']],
                        'power_state': VMWARE_POWER_STATES[raw_instance['runtime.powerState']],
                        'max_mem': max_mem,
                        'mem': max_mem,
                    'memory_mb': raw_instance.get('summary.config.memorySizeMB', 0),
                    'vcpus': int(raw_instance.get('summary.config.numCpu', 0)),
                        'runningTasks': running_tasks,
                        'vmFolder': vmFolder,
                        'node': self._nodename,
                        'net':raw_instance['guest.net']}]
            else:
                LOG.info(_("Skiped the instance uuid %(uuid)s , %(name)s due to duplication") % {'uuid': uuid, 'name': raw_instance['name']} )
        return instances

    def associate_alternate_uuid_for_instance(self, instance):
        return vm_util.associate_alternate_uuid_for_instance(self._session, instance)

    def _get_properties_from_objects(self, props, query):
        records = []
        while props:
            token = vm_util._get_token(props)
            for elem in props.objects:
                record = {}
                for prop in elem.propSet:
                    for key in query:
                        if prop.name == key:
                            record[key] = prop.val
                            break
                records += [record]
            if token:
                props = self._session._call_method(vim_util, "continue_to_get_objects", token)
            else:
                break

        return records
    # Vsettan-only end
