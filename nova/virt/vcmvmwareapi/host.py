# Copyright (c) 2013 Hewlett-Packard Development Company, L.P.
# Copyright (c) 2012 VMware, Inc.
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
Management class for host-related functions (start, reboot, etc).
"""

from oslo_utils import units
from oslo_utils import versionutils

from nova.compute import arch
from nova.compute import hv_type
from nova.compute import vm_mode
from nova import exception
from nova.virt.vcmvmwareapi import ds_util
from nova.virt.vcmvmwareapi import vim_util
from nova.virt.vcmvmwareapi import vm_util
from nova.virt.vcmvmwareapi import constants


def _get_ds_capacity_and_freespace(session, cluster=None,
                                   datastore_regex=None):
    try:
        ds = ds_util.get_datastore(session, cluster,
                                   datastore_regex)
        return ds.capacity, ds.freespace
    except exception.DatastoreNotFound:
        return 0, 0


class VCState(object):
    """Manages information about the vCenter cluster"""
    def __init__(self, session, host_name, cluster,
                 host=None, # Vsettan-only
                 resource_pool=None, # Vsettan-only
                 datastore_regex=None,
                 storage_pod=None): # Vsettan-only
        super(VCState, self).__init__()
        self._session = session
        self._host_name = host_name
        self._cluster = cluster
        self._datastore_regex = datastore_regex
        #Vsettan-only start
        self._host = host
        self._resource_pool = resource_pool
        self._storage_pod = storage_pod
        # Vsettan-only end
        self._stats = {}

        self.update_status()

    def get_host_stats(self, refresh=False):
        """Return the current state of the cluster. If 'refresh' is
        True, run the update first.
        """
        if refresh or not self._stats:
            self.update_status()
        return self._stats

    def update_status(self):
        """Update the current state of the cluster."""
        # Vsettan-only start
        capacity, freespace = ds_util.\
                get_ds_capacity_freespace_for_compute(self._session,
                                                      self._cluster,
                                                      self._host,
                                                      self._datastore_regex,
                                                      self._storage_pod)
        # Vsettan-only end

        # Vsettan-only (prs-related) start
        # Get cpu and memory info from ESXi host's metrics 
        #  when using root resource pool
        if vm_util.is_root_resource_pool(self._session,
                                         resource_Pool=self._resource_pool):
            host_data = vm_util.get_stats_from_host(self._session, self._host)
            host_data["disk_total"] = capacity / units.Gi
            host_data["disk_available"] = freespace / units.Gi
            host_data["disk_used"] = \
                    host_data["disk_total"] - host_data["disk_available"]
            host_data["hypervisor_hostname"] = self._host_name
            host_data["supported_instances"] = [
                     (arch.I686, constants.HYPERVISOR_IMAGE_TYPE, vm_mode.HVM),
                     (arch.X86_64, constants.HYPERVISOR_IMAGE_TYPE, vm_mode.HVM)]
            self._stats = host_data
            return host_data
        # Vsettan-only (prs-related) end

        # Get cpu, memory stats from the cluster
        stats = vm_util.\
                get_stats_from_cluster(self._session,
                                       cluster=self._cluster,
                                       resource_pool=self._resource_pool) # Vsettan-only
        about_info = self._session._call_method(vim_util, "get_about_info")
        data = {}
        data["vcpus"] = stats['vcpus']
        data["disk_total"] = capacity / units.Gi
        data["disk_available"] = freespace / units.Gi
        data["disk_used"] = data["disk_total"] - data["disk_available"]
        data["host_memory_total"] = stats['mem']['total']
        data["host_memory_free"] = stats['mem']['free']
        data["hypervisor_type"] = about_info.name
        data["hypervisor_version"] = versionutils.convert_version_to_int(
                str(about_info.version))
        data["hypervisor_hostname"] = self._host_name
        data["supported_instances"] = [
            (arch.I686, hv_type.VMWARE, vm_mode.HVM),
            (arch.X86_64, hv_type.VMWARE, vm_mode.HVM)]

        self._stats = data
        return data
