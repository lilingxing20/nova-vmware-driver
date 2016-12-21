# Copyright (c) 2014 VMware, Inc.
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
Datastore utility functions
"""
## add by Vsettan-only
import random 
import re
from oslo_config import cfg
## end by Vsettan-only

import collections

from oslo_log import log as logging
from oslo_vmware import exceptions as vexc
from oslo_vmware.objects import datastore as ds_obj
from oslo_vmware import pbm
from oslo_vmware import vim_util as vutil

from nova import exception
from nova.i18n import _, _LE, _LI
from nova.virt.vcmvmwareapi import constants
from nova.virt.vcmvmwareapi import vim_util
from nova.virt.vcmvmwareapi import vm_util

#Vsettan-only start
CONF = cfg.CONF
#Vsettan-only end

LOG = logging.getLogger(__name__)
ALL_SUPPORTED_DS_TYPES = frozenset([constants.DATASTORE_TYPE_VMFS,
                                    constants.DATASTORE_TYPE_NFS,
                                    constants.DATASTORE_TYPE_NFS41,
                                    constants.DATASTORE_TYPE_VSAN])


DcInfo = collections.namedtuple('DcInfo',
                                ['ref', 'name', 'vmFolder'])

# A cache for datastore/datacenter mappings. The key will be
# the datastore moref. The value will be the DcInfo object.
_DS_DC_MAPPING = {}

# NOTE(mdbooth): this convenience function is temporarily duplicated in
# vm_util. The correct fix is to handle paginated results as they are returned
# from the relevant vim_util function. However, vim_util is currently
# effectively deprecated as we migrate to oslo.vmware. This duplication will be
# removed when we fix it properly in oslo.vmware.
def _get_token(results):
    """Get the token from the property results."""
    return getattr(results, 'token', None)


def _select_datastore(session, data_stores, best_match, datastore_regex=None,
                      storage_policy=None,
                      allowed_ds_types=ALL_SUPPORTED_DS_TYPES,
                      storage_pod=None, # Vsettan-only
                      limit_size=0): # Vsettan-only
    """Find the most preferable datastore in a given RetrieveResult object.

    :param session: vcmvmwareapi session
    :param data_stores: a RetrieveResult object from vSphere API call
    :param best_match: the current best match for datastore
    :param datastore_regex: an optional regular expression to match names
    :param storage_policy: storage policy for the datastore
    :param allowed_ds_types: a list of acceptable datastore type names
    :param storage_pod: an optional object to match datastore's parent #Vsettan-only
    :return: datastore_ref, datastore_name, capacity, freespace
    """

    if storage_policy:
        matching_ds = _filter_datastores_matching_storage_policy(
            session, data_stores, storage_policy)
        if not matching_ds:
            return best_match
    else:
        matching_ds = data_stores

    available_ds = [] # Vsettan-onlys
    # data_stores is actually a RetrieveResult object from vSphere API call
    for obj_content in matching_ds.objects:
        # the propset attribute "need not be set" by returning API
        if not hasattr(obj_content, 'propSet'):
            continue

        propdict = vm_util.propset_dict(obj_content.propSet)
        # Vsettan-only begin
        # Filtering out the datastores which do not belong to
        # user defined StoragePod
        if storage_pod and _is_ds_not_in_storagepod(propdict, storage_pod):
            continue
        # Vsettan-only end
        if _is_datastore_valid(propdict, datastore_regex, allowed_ds_types):
            new_ds = ds_obj.Datastore(
                    ref=obj_content.obj,
                    name=propdict['summary.name'],
                    capacity=propdict['summary.capacity'],
                    freespace=propdict['summary.freeSpace'])
            # favor datastores with more free space
            # Vsettan-only start
            if ((best_match is None and
                 new_ds.freespace > limit_size) or
                (best_match is not None and
                 new_ds.freespace > best_match.freespace)):
                best_match = new_ds
                available_ds.append(new_ds)
            # Vsettan-only end

    # Vsettan-only begin
    # If random_datastore is true, choose a random datastore from available ones
    if CONF.vmware.random_datastore and available_ds:
        best_match = available_ds[random.randint(0, len(available_ds) - 1)]
    # Vsettan-only end

    return best_match


def _is_datastore_valid(propdict, datastore_regex, ds_types):
    """Checks if a datastore is valid based on the following criteria.

       Criteria:
       - Datastore is accessible
       - Datastore is not in maintenance mode (optional)
       - Datastore's type is one of the given ds_types
       - Datastore matches the supplied regex (optional)

       :param propdict: datastore summary dict
       :param datastore_regex : Regex to match the name of a datastore.
    """

    # Local storage identifier vSphere doesn't support CIFS or
    # vfat for datastores, therefore filtered
    return (propdict.get('summary.accessible') and
            (propdict.get('summary.maintenanceMode') is None or
             propdict.get('summary.maintenanceMode') == 'normal') and
            propdict['summary.type'] in ds_types and
            ((datastore_regex is None or 
             datastore_regex.match(propdict['summary.name'])) and
             _is_ds_name_legal(propdict['summary.name']))) # Vsettan-only



def get_datastore(session, cluster,
                  host=None, #Vsettan-only
                  storage_pod=None, #Vsettan-only
                  datastore_regex=None,
                  storage_policy=None,
                  allowed_ds_types=ALL_SUPPORTED_DS_TYPES,
                  limit_size=0):#Vsettan-only
    """Get the datastore list and choose the most preferable one."""
    #Vsettan-only start
    if cluster is None and host is None:
        data_stores = session._call_method(vim_util, "get_objects",
                    "Datastore", ["summary.type", "summary.name",
                                  "summary.capacity", "summary.freeSpace",
                                  "summary.accessible",
                                  "summary.maintenanceMode",
                                  "parent"]) # Vsettan-only add parent
    else:
        if cluster is not None:
            datastore_ret = session._call_method(
                                        vim_util,
                                        "get_dynamic_property", cluster,
                                        "ClusterComputeResource", "datastore")
        else:
            datastore_ret = session._call_method(
                                        vim_util,
                                        "get_dynamic_property", host,
                                        "HostSystem", "datastore")
    # If there are no hosts in the cluster then an empty string is
    # returned
        if not datastore_ret:
            raise exception.DatastoreNotFound()
    
        data_store_mors = datastore_ret.ManagedObjectReference
        data_stores = session._call_method(vim_util,
                                "get_properties_for_a_collection_of_objects",
                                "Datastore", data_store_mors,
                                ["summary.type", "summary.name",
                                 "summary.capacity", "summary.freeSpace",
                                 "summary.accessible",
                                 "summary.maintenanceMode",
                                 "parent"])  # Vsettan-only add parent
    #Vsettan-only end
    best_match = None
    while data_stores:
        best_match = _select_datastore(session,
                                       data_stores,
                                       best_match,
                                       datastore_regex,
                                       storage_policy,
                                       allowed_ds_types,
                                       storage_pod, # Vsettan-only
                                       limit_size) # Vsettan-only
        token = _get_token(data_stores)
        if not token:
            break
        data_stores = session._call_method(vim_util,
                                           "continue_to_get_objects",
                                           token)
    if best_match:
        return best_match

    if storage_policy:
        raise exception.DatastoreNotFound(
            _("Storage policy %s did not match any datastores")
            % storage_policy)
    elif datastore_regex:
        raise exception.DatastoreNotFound(
            _("Datastore regex %s did not match any datastores or "
              "datastores not have enough free disk space.")
            % datastore_regex.pattern)
    else:
        raise exception.DatastoreNotFound()


def _get_allowed_datastores(data_stores, datastore_regex,
                            storage_pod): #Vsettan-only
    allowed = []
    for obj_content in data_stores.objects:
        # the propset attribute "need not be set" by returning API
        if not hasattr(obj_content, 'propSet'):
            continue

        propdict = vm_util.propset_dict(obj_content.propSet)

        # Vsettan-only begin
        # Filtering out the datastores which do not belong to
        # user defined StoragePod
        if storage_pod and _is_ds_not_in_storagepod(propdict, storage_pod):
            continue
        # Vsettan-only end

        if _is_datastore_valid(propdict,
                               datastore_regex,
                               ALL_SUPPORTED_DS_TYPES):
            ds_capacity = propdict["summary.capacity"] # Vsettan-only
            ds_freespace = propdict["summary.freeSpace"] # Vsettan-only
            allowed.append(ds_obj.Datastore(ref=obj_content.obj,
                                            name=propdict['summary.name'],
                                            freespace=ds_freespace, capacity=ds_capacity)) #Vsettan-only

    return allowed


def get_available_datastores(session, cluster=None,
                             host=None, #Vsettan-only
                             datastore_regex=None,
                             storage_pod=None): #Vsettan-only
    """Get the datastore list and choose the first local storage."""
    if cluster:
        mobj = cluster
        resource_type = "ClusterComputeResource"
    # Vsettan-only start
    elif host:
        mobj = host
        resource_type = "HostSystem"
    # Vsettan-only end
    else:
        mobj = vm_util.get_host_ref(session)
        resource_type = "HostSystem"
    ds = session._call_method(vim_util, "get_dynamic_property", mobj,
                              resource_type, "datastore")
    if not ds:
        return []
    data_store_mors = ds.ManagedObjectReference
    # NOTE(garyk): use utility method to retrieve remote objects
    data_stores = session._call_method(vim_util,
            "get_properties_for_a_collection_of_objects",
            "Datastore", data_store_mors,
            ["summary.type", "summary.name", "summary.accessible",
             "summary.maintenanceMode",
             "summary.capacity", "summary.freeSpace", "parent"]) #Vsettan-only

    allowed = []
    while data_stores:
        allowed.extend(_get_allowed_datastores(data_stores, datastore_regex,
                                               storage_pod)) #Vsettan-only
        token = _get_token(data_stores)
        if not token:
            break

        data_stores = session._call_method(vim_util,
                                           "continue_to_get_objects",
                                           token)
    return allowed


def get_allowed_datastore_types(disk_type):
    if disk_type == constants.DISK_TYPE_STREAM_OPTIMIZED:
        return ALL_SUPPORTED_DS_TYPES
    return ALL_SUPPORTED_DS_TYPES - frozenset([constants.DATASTORE_TYPE_VSAN])


def file_delete(session, ds_path, dc_ref):
    LOG.debug("Deleting the datastore file %s", ds_path)
    vim = session.vim
    file_delete_task = session._call_method(
            vim,
            "DeleteDatastoreFile_Task",
            vim.service_content.fileManager,
            name=str(ds_path),
            datacenter=dc_ref)
    session._wait_for_task(file_delete_task)
    LOG.debug("Deleted the datastore file")


def file_copy(session, src_file, src_dc_ref, dst_file, dst_dc_ref):
    LOG.debug("Copying the datastore file from %(src)s to %(dst)s",
              {'src': src_file, 'dst': dst_file})
    vim = session.vim
    copy_task = session._call_method(
            vim,
            "CopyDatastoreFile_Task",
            vim.service_content.fileManager,
            sourceName=src_file,
            sourceDatacenter=src_dc_ref,
            destinationName=dst_file,
            destinationDatacenter=dst_dc_ref)
    session._wait_for_task(copy_task)
    LOG.debug("Copied the datastore file")


def disk_move(session, dc_ref, src_file, dst_file):
    """Moves the source virtual disk to the destination.

    The list of possible faults that the server can return on error
    include:

    * CannotAccessFile: Thrown if the source file or folder cannot be
      moved because of insufficient permissions.
    * FileAlreadyExists: Thrown if a file with the given name already
      exists at the destination.
    * FileFault: Thrown if there is a generic file error
    * FileLocked: Thrown if the source file or folder is currently
      locked or in use.
    * FileNotFound: Thrown if the file or folder specified by sourceName
      is not found.
    * InvalidDatastore: Thrown if the operation cannot be performed on
      the source or destination datastores.
    * NoDiskSpace: Thrown if there is not enough space available on the
      destination datastore.
    * RuntimeFault: Thrown if any type of runtime fault is thrown that
      is not covered by the other faults; for example,
      a communication error.

    """
    LOG.debug("Moving virtual disk from %(src)s to %(dst)s.",
              {'src': src_file, 'dst': dst_file})
    move_task = session._call_method(
            session.vim,
            "MoveVirtualDisk_Task",
            session.vim.service_content.virtualDiskManager,
            sourceName=str(src_file),
            sourceDatacenter=dc_ref,
            destName=str(dst_file),
            destDatacenter=dc_ref,
            force=False)
    session._wait_for_task(move_task)
    LOG.info(_LI("Moved virtual disk from %(src)s to %(dst)s."),
             {'src': src_file, 'dst': dst_file})


def disk_copy(session, dc_ref, src_file, dst_file):
    """Copies the source virtual disk to the destination."""
    LOG.debug("Copying virtual disk from %(src)s to %(dst)s.",
              {'src': src_file, 'dst': dst_file})
    copy_disk_task = session._call_method(
            session.vim,
            "CopyVirtualDisk_Task",
            session.vim.service_content.virtualDiskManager,
            sourceName=str(src_file),
            sourceDatacenter=dc_ref,
            destName=str(dst_file),
            destDatacenter=dc_ref,
            force=False)
    session._wait_for_task(copy_disk_task)
    LOG.info(_LI("Copied virtual disk from %(src)s to %(dst)s."),
             {'src': src_file, 'dst': dst_file})


def disk_delete(session, dc_ref, file_path):
    """Deletes a virtual disk."""
    LOG.debug("Deleting virtual disk %s", file_path)
    delete_disk_task = session._call_method(
            session.vim,
            "DeleteVirtualDisk_Task",
            session.vim.service_content.virtualDiskManager,
            name=str(file_path),
            datacenter=dc_ref)
    session._wait_for_task(delete_disk_task)
    LOG.info(_LI("Deleted virtual disk %s."), file_path)


def file_move(session, dc_ref, src_file, dst_file):
    """Moves the source file or folder to the destination.

    The list of possible faults that the server can return on error
    include:

    * CannotAccessFile: Thrown if the source file or folder cannot be
      moved because of insufficient permissions.
    * FileAlreadyExists: Thrown if a file with the given name already
      exists at the destination.
    * FileFault: Thrown if there is a generic file error
    * FileLocked: Thrown if the source file or folder is currently
      locked or in use.
    * FileNotFound: Thrown if the file or folder specified by sourceName
      is not found.
    * InvalidDatastore: Thrown if the operation cannot be performed on
      the source or destination datastores.
    * NoDiskSpace: Thrown if there is not enough space available on the
      destination datastore.
    * RuntimeFault: Thrown if any type of runtime fault is thrown that
      is not covered by the other faults; for example,
      a communication error.

    """
    LOG.debug("Moving file from %(src)s to %(dst)s.",
              {'src': src_file, 'dst': dst_file})
    vim = session.vim
    move_task = session._call_method(
            vim,
            "MoveDatastoreFile_Task",
            vim.service_content.fileManager,
            sourceName=str(src_file),
            sourceDatacenter=dc_ref,
            destinationName=str(dst_file),
            destinationDatacenter=dc_ref)
    session._wait_for_task(move_task)
    LOG.debug("File moved")


def search_datastore_spec(client_factory, file_name):
    """Builds the datastore search spec."""
    search_spec = client_factory.create('ns0:HostDatastoreBrowserSearchSpec')
    search_spec.matchPattern = [file_name]
    search_spec.details = client_factory.create('ns0:FileQueryFlags')
    search_spec.details.fileOwner = False
    search_spec.details.fileSize = True
    search_spec.details.fileType = False
    search_spec.details.modification = False
    return search_spec


def file_exists(session, ds_browser, ds_path, file_name):
    """Check if the file exists on the datastore."""
    client_factory = session.vim.client.factory
    search_spec = search_datastore_spec(client_factory, file_name)
    search_task = session._call_method(session.vim,
                                             "SearchDatastore_Task",
                                             ds_browser,
                                             datastorePath=str(ds_path),
                                             searchSpec=search_spec)
    try:
        task_info = session._wait_for_task(search_task)
    except vexc.FileNotFoundException:
        return False

    file_exists = (getattr(task_info.result, 'file', False) and
                   task_info.result.file[0].path == file_name)
    return file_exists


def file_size(session, ds_browser, ds_path, file_name):
    """Returns the size of the specified file."""
    client_factory = session.vim.client.factory
    search_spec = search_datastore_spec(client_factory, file_name)
    search_task = session._call_method(session.vim,
                                       "SearchDatastore_Task",
                                       ds_browser,
                                       datastorePath=str(ds_path),
                                       searchSpec=search_spec)
    task_info = session._wait_for_task(search_task)
    if hasattr(task_info.result, 'file'):
        return task_info.result.file[0].fileSize


def mkdir(session, ds_path, dc_ref):
    """Creates a directory at the path specified. If it is just "NAME",
    then a directory with this name is created at the topmost level of the
    DataStore.
    """
    LOG.debug("Creating directory with path %s", ds_path)
    session._call_method(session.vim, "MakeDirectory",
            session.vim.service_content.fileManager,
            name=str(ds_path), datacenter=dc_ref,
            createParentDirectories=True)
    LOG.debug("Created directory with path %s", ds_path)


def get_sub_folders(session, ds_browser, ds_path):
    """Return a set of subfolders for a path on a datastore.

    If the path does not exist then an empty set is returned.
    """
    search_task = session._call_method(
            session.vim,
            "SearchDatastore_Task",
            ds_browser,
            datastorePath=str(ds_path))
    try:
        task_info = session._wait_for_task(search_task)
    except vexc.FileNotFoundException:
        return set()
    # populate the folder entries
    if hasattr(task_info.result, 'file'):
        return set([file.path for file in task_info.result.file])
    return set()


def _filter_datastores_matching_storage_policy(session, data_stores,
                                               storage_policy):
    """Get datastores matching the given storage policy.

    :param data_stores: the list of retrieve result wrapped datastore objects
    :param storage_policy: the storage policy name
    :return the list of datastores conforming to the given storage policy
    """
    profile_id = pbm.get_profile_id_by_name(session, storage_policy)
    if profile_id:
        factory = session.pbm.client.factory
        ds_mors = [oc.obj for oc in data_stores.objects]
        hubs = pbm.convert_datastores_to_hubs(factory, ds_mors)
        matching_hubs = pbm.filter_hubs_by_profile(session, hubs,
                                                   profile_id)
        if matching_hubs:
            matching_ds = pbm.filter_datastores_by_hubs(matching_hubs,
                                                        ds_mors)
            object_contents = [oc for oc in data_stores.objects
                               if oc.obj in matching_ds]
            data_stores.objects = object_contents
            return data_stores
    LOG.error(_LE("Unable to retrieve storage policy with name %s"),
              storage_policy)

## Mitak update
def _update_datacenter_cache_from_objects(session, dcs):
    """Updates the datastore/datacenter cache."""
    while dcs:
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
                _DS_DC_MAPPING[ds_ref] = DcInfo(ref=dc_ref, name=name,
                                                vmFolder=vmFolder)
        dcs = session._call_method(vutil, 'continue_retrieval', dcs)


def get_dc_info(session, ds_ref):
    """Get the datacenter name and the reference."""
    dc_info = _DS_DC_MAPPING.get(ds_ref.value)
    if not dc_info:
        dcs = session._call_method(vim_util, "get_objects",
                "Datacenter", ["name", "datastore", "vmFolder"])
        _update_datacenter_cache_from_objects(session, dcs)
        dc_info = _DS_DC_MAPPING.get(ds_ref.value)
    return dc_info


def dc_cache_reset():
    global _DS_DC_MAPPING
    _DS_DC_MAPPING = {}


def get_connected_hosts(session, datastore):
    """Get all the hosts to which the datastore is connected.

    :param datastore: Reference to the datastore entity
    :return: List of managed object references of all connected
             hosts
    """
    host_mounts = session._call_method(vutil, 'get_object_property',
                                       datastore, 'host')
    if not hasattr(host_mounts, 'DatastoreHostMount'):
        return []

    connected_hosts = []
    for host_mount in host_mounts.DatastoreHostMount:
        connected_hosts.append(host_mount.key.value)

    return connected_hosts
## Mitak update end


# Vsettan-only begin
def get_storage_pod_ref_by_name(session, storage_pod_name):
    """Get reference to the StoragePod with the name specified."""
    if storage_pod_name is None:
        return None
    pods = session._call_method(vim_util, "get_objects",
                                "StoragePod", ["name"])
    return vm_util._get_object_from_results(session, pods, storage_pod_name,
                                    vm_util._get_object_for_value)
# Vsettan-only end


# Vsettan-only start
def get_ds_capacity_freespace_for_compute(session, cluster=None,
                                          host=None, datastore_regex=None,
                                          storage_pod=None):
    """Get all accessible datastores' capacity and freespace
       for certain cluster or host.
    """
    datastores = get_available_datastores(session, cluster, host, datastore_regex,
                                          storage_pod) #Vsettan-only
    total_freespace = 0
    total_capacity = 0
    for ds in datastores:
        total_freespace += ds.freespace
        total_capacity += ds.capacity
    return total_capacity, total_freespace

def build_datastore_path(datastore_name, path):
    """Build the datastore compliant path."""
    return "[%s] %s" % (datastore_name, path)

# Vsettan-only end


# Vsettan-only start
def _is_ds_name_legal(name):
    name_pattern = "[\s0-9a-zA-Z_-]*"
    m = re.match(name_pattern, name)
    if m.group() != name:
        LOG.warn(("Illegal datastore name '%s': can only contain "
                   "numbers, lowercase and uppercase letters, whitespaces, '_' "
                   "and '-'.") % name)
        return False
    return True
# Vsettan-only end


# Vsettan-only start
def _is_ds_not_in_storagepod(propdict, storage_pod):
    ds_parent = propdict['parent']
    if ds_parent is None:
        return True
    if ((ds_parent._type != storage_pod._type) or
        (ds_parent.value != storage_pod.value)):
        return True
    return False


def get_datastore_by_ref(session, ds_ref):
    lst_properties = ["summary.type", "summary.name",
                      "summary.capacity", "summary.freeSpace"]
    props = session._call_method(vim_util, "get_object_properties",
                                 None, ds_ref, "Datastore", lst_properties)
    query = vm_util.get_values_from_object_properties(session, props)
    return ds_obj.Datastore(ds_ref, query["summary.name"],
                     capacity=query["summary.capacity"],
                     freespace=query["summary.freeSpace"])

# Vsettan-only end


## add by lixx
def get_datacenters(session, properties_list=['name'], detail=False):
    """ Get datacenters for vCenter server. """
    if detail:
        properties_list = ["alarmActionsEnabled","datastore","name","network","overallStatus","parent"]
    if not properties_list: 
        return ["alarmActionsEnabled","availableField","configIssue","configStatus","configuration","customValue","datastore","datastoreFolder","declaredAlarmState","disabledMethod","effectiveRole","hostFolder","name","network","networkFolder","overallStatus","parent","permission","recentTask","tag","triggeredAlarmState","value","vmFolder"]
    retrieve_result = session._call_method(vim_util, "get_objects",
                                           "Datacenter", properties_list)
    dcs_info_list = vm_util.retrieve_result_propset_dict_list(session, 
                                                              retrieve_result)
    return dcs_info_list


def get_datastores(session, cluster=None, host=None, 
                   properties_list=['name'], detail=False):
    if detail:
        properties_list = ["alarmActionsEnabled","name","overallStatus","parent","summary.capacity","summary.freeSpace","summary.type","summary.accessible","summary.maintenanceMode","vm"]
    if not properties_list: 
        return ["alarmActionsEnabled","availableField","browser","capability","configIssue","configStatus","customValue","declaredAlarmState","disabledMethod","effectiveRole","host","info","iormConfiguration","name","overallStatus","parent","permission","recentTask","summary","tag","triggeredAlarmState","value","vm"]
    """ Get datastores for vCenter cluster. """
    if cluster is None and host is None:
        retrieve_result = session._call_method(vim_util, "get_objects",
                                               "Datastore", properties_list)
    else:
        if cluster is not None:
            datastore_ret = session._call_method(
                                        vim_util,
                                        "get_dynamic_property", cluster,
                                        "ClusterComputeResource", "datastore")
        else:
            datastore_ret = session._call_method(
                                        vim_util,
                                        "get_dynamic_property", host,
                                        "HostSystem", "datastore")
        # If there are no hosts in the cluster then an empty string is
        # returned
        if not datastore_ret:
            raise exception.DatastoreNotFound()
    
        data_store_mors = datastore_ret.ManagedObjectReference
        retrieve_result = vm_util.get_mor_properties(session, 
                                                    "Datastore", 
                                                    data_store_mors,
                                                    properties_list)
    datastores_list = vm_util.retrieve_result_propset_dict_list(session, 
                                                                retrieve_result)
    return datastores_list


def get_datastore_clusters(session, properties_list=['name'], detail=False):
    """ Get datastore clusters for vCenter server. """
    if detail:
        properties_list = ["alarmActionsEnabled","childEntity","name","overallStatus","parent","summary.capacity","summary.freeSpace"]
    if not properties_list:
        return ["alarmActionsEnabled","availableField","childEntity","childType","configIssue","configStatus","customValue","declaredAlarmState","disabledMethod","effectiveRole","name","overallStatus","parent","permission","podStorageDrsEntry","recentTask","summary","tag","triggeredAlarmState","value"]

    retrieve_result = session._call_method(vim_util, 
                                           "get_objects",
                                           "StoragePod",
                                           properties_list)
    ds_clusters = vm_util.retrieve_result_propset_dict_list(session, 
                                                            retrieve_result)
    ds_cluster_list = []
    for ds_cluster in ds_clusters:
        try:
            ds_child_aomor = ds_cluster.pop('childEntity')
            ds_datastores = vm_util.get_mor_properties(session, 
                                                       'Datastore', 
                                                       ds_child_aomor)
            ds_cluster['datastore'] = ds_datastores
        except Exception as excep:
            LOG.warn(_LE("Failed to get datastore cluster child datastore,\
                          warning references %s."), excep)
        ds_cluster_list.append(ds_cluster) 
    
    return ds_cluster_list


def get_esxi_hosts(session, cluster_name=None, 
                            properties_list=['name'], 
                            detail=False):
    """ Get esxi hosts for vCenter cluster. """
    if detail:
        properties_list = ["name", "parent", "datastore", "vm", "summary.hardware.vendor", "summary.hardware.model", "summary.hardware.uuid", "summary.hardware.memorySize", "summary.hardware.cpuModel", "summary.hardware.cpuMhz", "summary.hardware.numCpuPkgs", "summary.hardware.numCpuThreads", "summary.hardware.numNics", "summary.hardware.numHBAs", "summary.runtime.connectionState","summary.runtime.powerState","summary.runtime.bootTime", "summary.overallStatus", "summary.managementServerIp"]
    if not properties_list:
        return ['alarmActionsEnabled', 'availableField', 'capability', 'config', 'configIssue', 'configManager', 'configStatus', 'customValue', 'datastore', 'datastoreBrowser', 'declaredAlarmState', 'disabledMethod', 'effectiveRole', 'hardware', 'licensableResource', 'name', 'network', 'overallStatus', 'parent', 'permission', 'recentTask', 'runtime', 'summary', 'systemResources', 'tag', 'triggeredAlarmState', 'value', 'vm']

    if cluster_name:
        cluster_obj = vm_util.get_cluster_ref_by_name(session, cluster_name)
        # Get the Host and Resource Pool Managed Object Refs
        host_aomor = session._call_method(vim_util, "get_dynamic_property", 
                                          cluster_obj, 
                                          "ClusterComputeResource", "host")
        host_mors = host_aomor.ManagedObjectReference
        retrieve_result =  session._call_method(vim_util, 
                                "get_properties_for_a_collection_of_objects",
                                "HostSystem", host_mors, properties_list)
    else:
        retrieve_result = session._call_method(vim_util, 'get_objects', 'HostSystem', 
                                     properties_list)
    hosts_list = vm_util.retrieve_result_propset_dict_list(session, 
                                                           retrieve_result)
    return hosts_list

