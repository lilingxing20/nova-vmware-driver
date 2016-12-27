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
The VMware API utility module.
"""

from oslo_config import cfg
from oslo_log import log as logging
from oslo_vmware import vim_util as vutil
import suds

from nova.i18n import _LW

vmware_opts = cfg.IntOpt('maximum_objects', default=100,
                         help='The maximum number of ObjectContent data '
                              'objects that should be returned in a single '
                              'result. A positive value will cause the '
                              'operation to suspend the retrieval when the '
                              'count of objects reaches the specified '
                              'maximum. The server may still limit the count '
                              'to something less than the configured value. '
                              'Any remaining objects may be retrieved with '
                              'additional requests.')
CONF = cfg.CONF
CONF.register_opt(vmware_opts, 'vmware')
LOG = logging.getLogger(__name__)


def object_to_dict(obj, list_depth=1):
    """Convert Suds object into serializable format.

    The calling function can limit the amount of list entries that
    are converted.
    """
    d = {}
    for k, v in suds.sudsobject.asdict(obj).iteritems():
        if hasattr(v, '__keylist__'):
            d[k] = object_to_dict(v, list_depth=list_depth)
        elif isinstance(v, list):
            d[k] = []
            used = 0
            for item in v:
                used = used + 1
                if used > list_depth:
                    break
                if hasattr(item, '__keylist__'):
                    d[k].append(object_to_dict(item, list_depth=list_depth))
                else:
                    d[k].append(item)
        else:
            d[k] = v
    return d


def get_object_properties(vim, collector, mobj, type, properties):
    """Gets the properties of the Managed object specified."""
    client_factory = vim.client.factory
    if mobj is None:
        return None
    usecoll = collector
    if usecoll is None:
        usecoll = vim.service_content.propertyCollector
    property_filter_spec = client_factory.create('ns0:PropertyFilterSpec')
    property_spec = client_factory.create('ns0:PropertySpec')
    property_spec.all = (properties is None or len(properties) == 0)
    property_spec.pathSet = properties
    property_spec.type = type
    object_spec = client_factory.create('ns0:ObjectSpec')
    object_spec.obj = mobj
    object_spec.skip = False
    property_filter_spec.propSet = [property_spec]
    property_filter_spec.objectSet = [object_spec]
    options = client_factory.create('ns0:RetrieveOptions')
    options.maxObjects = CONF.vmware.maximum_objects
    return vim.RetrievePropertiesEx(usecoll, specSet=[property_filter_spec],
                                    options=options)


def get_dynamic_property(vim, mobj, type, property_name):
    """Gets a particular property of the Managed Object."""
    property_dict = get_dynamic_properties(vim, mobj, type, [property_name])
    return property_dict.get(property_name)


def get_dynamic_properties(vim, mobj, type, property_names):
    """Gets the specified properties of the Managed Object."""
    obj_content = get_object_properties(vim, None, mobj, type, property_names)
    if obj_content is None:
        return {}
    if hasattr(obj_content, 'token'):
        cancel_retrieve(vim, obj_content.token)
    property_dict = {}
    if obj_content.objects:
        if hasattr(obj_content.objects[0], 'propSet'):
            dynamic_properties = obj_content.objects[0].propSet
            if dynamic_properties:
                for prop in dynamic_properties:
                    property_dict[prop.name] = prop.val
        # The object may have information useful for logging
        if hasattr(obj_content.objects[0], 'missingSet'):
            for m in obj_content.objects[0].missingSet:
                LOG.warning(_LW("Unable to retrieve value for %(path)s "
                                "Reason: %(reason)s"),
                            {'path': m.path,
                             'reason': m.fault.localizedMessage})
    return property_dict


def get_objects(vim, type, properties_to_collect=None, all=False):
    """Gets the list of objects of the type specified."""
    #Vsettan-only start
    #(Community use oslo.vmware utils will miss the build_recursive_traversal_spec which is Vsettan-only)
    if not properties_to_collect:
        properties_to_collect = ["name"]

    client_factory = vim.client.factory
    object_spec = build_object_spec(client_factory,
                        vim.service_content.rootFolder,
                        [build_recursive_traversal_spec(client_factory)])
    property_spec = build_property_spec(client_factory, type=type,
                                properties_to_collect=properties_to_collect,
                                all_properties=all)
    property_filter_spec = build_property_filter_spec(client_factory,
                                [property_spec],
                                [object_spec])
    options = client_factory.create('ns0:RetrieveOptions')
    options.maxObjects = CONF.vmware.maximum_objects
    return vim.RetrievePropertiesEx(
            vim.service_content.propertyCollector,
            specSet=[property_filter_spec], options=options)
    #Vsettan-only end

def get_inner_objects(vim, base_obj, path, inner_type,
                      properties_to_collect=None, all=False):
    """Gets the list of inner objects of the type specified."""
    client_factory = vim.client.factory
    base_type = base_obj._type
    traversal_spec = vutil.build_traversal_spec(client_factory, 'inner',
                                                base_type, path, False, [])
    object_spec = vutil.build_object_spec(client_factory,
                                          base_obj,
                                          [traversal_spec])
    property_spec = vutil.build_property_spec(client_factory, type_=inner_type,
                                properties_to_collect=properties_to_collect,
                                all_properties=all)
    property_filter_spec = vutil.build_property_filter_spec(client_factory,
                                [property_spec], [object_spec])
    options = client_factory.create('ns0:RetrieveOptions')
    options.maxObjects = CONF.vmware.maximum_objects
    return vim.RetrievePropertiesEx(
            vim.service_content.propertyCollector,
            specSet=[property_filter_spec], options=options)


def cancel_retrieve(vim, token):
    """Cancels the retrieve operation."""
    return vim.CancelRetrievePropertiesEx(
            vim.service_content.propertyCollector,
            token=token)


def continue_to_get_objects(vim, token):
    """Continues to get the list of objects of the type specified."""
    return vim.ContinueRetrievePropertiesEx(
            vim.service_content.propertyCollector,
            token=token)


def get_prop_spec(client_factory, spec_type, properties):
    """Builds the Property Spec Object."""
    prop_spec = client_factory.create('ns0:PropertySpec')
    prop_spec.type = spec_type
    prop_spec.pathSet = properties
    return prop_spec


def get_obj_spec(client_factory, obj, select_set=None):
    """Builds the Object Spec object."""
    obj_spec = client_factory.create('ns0:ObjectSpec')
    obj_spec.obj = obj
    obj_spec.skip = False
    if select_set is not None:
        obj_spec.selectSet = select_set
    return obj_spec


def get_prop_filter_spec(client_factory, obj_spec, prop_spec):
    """Builds the Property Filter Spec Object."""
    prop_filter_spec = client_factory.create('ns0:PropertyFilterSpec')
    prop_filter_spec.propSet = prop_spec
    prop_filter_spec.objectSet = obj_spec
    return prop_filter_spec


def get_properties_for_a_collection_of_objects(vim, type,
                                               obj_list, properties):
    """Gets the list of properties for the collection of
    objects of the type specified.
    """
    client_factory = vim.client.factory
    if len(obj_list) == 0:
        return []
    prop_spec = get_prop_spec(client_factory, type, properties)
    lst_obj_specs = []
    for obj in obj_list:
        lst_obj_specs.append(get_obj_spec(client_factory, obj))
    prop_filter_spec = get_prop_filter_spec(client_factory,
                                            lst_obj_specs, [prop_spec])
    options = client_factory.create('ns0:RetrieveOptions')
    options.maxObjects = CONF.vmware.maximum_objects
    return vim.RetrievePropertiesEx(
            vim.service_content.propertyCollector,
            specSet=[prop_filter_spec], options=options)


def get_about_info(vim):
    """Get the About Info from the service content."""
    return vim.service_content.about


def get_entity_name(session, entity):
    return session._call_method(vutil, 'get_object_property',
                                entity, 'name')

# Vsettan-only start
def build_selection_spec(client_factory, name):
    """Builds the selection spec."""
    sel_spec = client_factory.create('ns0:SelectionSpec')
    sel_spec.name = name
    return sel_spec


def build_traversal_spec(client_factory, name, spec_type, path, skip,
                         select_set):
    """Builds the traversal spec object."""
    traversal_spec = client_factory.create('ns0:TraversalSpec')
    traversal_spec.name = name
    traversal_spec.type = spec_type
    traversal_spec.path = path
    traversal_spec.skip = skip
    traversal_spec.selectSet = select_set
    return traversal_spec


def build_recursive_traversal_spec(client_factory):
    """Builds the Recursive Traversal Spec to traverse the object managed
    object hierarchy.
    """
    visit_folders_select_spec = build_selection_spec(client_factory,
                                    "visitFolders")
    # For getting to hostFolder from datacenter
    dc_to_hf = build_traversal_spec(client_factory, "dc_to_hf", "Datacenter",
                                    "hostFolder", False,
                                    [visit_folders_select_spec])
    # For getting to vmFolder from datacenter
    dc_to_vmf = build_traversal_spec(client_factory, "dc_to_vmf", "Datacenter",
                                     "vmFolder", False,
                                     [visit_folders_select_spec])
    # Vsettan-only begin
    # For getting to datastoreFolder from datacenter
    dc_to_df = build_traversal_spec(client_factory, "dc_to_df", "Datacenter",
                                    "datastoreFolder", False,
                                    [visit_folders_select_spec])
    # Vsettan-only end
    # For getting Host System to virtual machine
    h_to_vm = build_traversal_spec(client_factory, "h_to_vm", "HostSystem",
                                   "vm", False,
                                   [visit_folders_select_spec])

    # For getting to Host System from Compute Resource
    cr_to_h = build_traversal_spec(client_factory, "cr_to_h",
                                   "ComputeResource", "host", False, [])

    # For getting to datastore from Compute Resource
    cr_to_ds = build_traversal_spec(client_factory, "cr_to_ds",
                                    "ComputeResource", "datastore", False, [])

    rp_to_rp_select_spec = build_selection_spec(client_factory, "rp_to_rp")
    rp_to_vm_select_spec = build_selection_spec(client_factory, "rp_to_vm")
    # For getting to resource pool from Compute Resource
    cr_to_rp = build_traversal_spec(client_factory, "cr_to_rp",
                                "ComputeResource", "resourcePool", False,
                                [rp_to_rp_select_spec, rp_to_vm_select_spec])

    # For getting to child res pool from the parent res pool
    rp_to_rp = build_traversal_spec(client_factory, "rp_to_rp", "ResourcePool",
                                "resourcePool", False,
                                [rp_to_rp_select_spec, rp_to_vm_select_spec])

    # For getting to Virtual Machine from the Resource Pool
    rp_to_vm = build_traversal_spec(client_factory, "rp_to_vm", "ResourcePool",
                                "vm", False,
                                [rp_to_rp_select_spec, rp_to_vm_select_spec])

    # Get the assorted traversal spec which takes care of the objects to
    # be searched for from the root folder
    traversal_spec = build_traversal_spec(client_factory, "visitFolders",
                                "Folder", "childEntity", False,
                                [visit_folders_select_spec, dc_to_hf,
                                dc_to_vmf, cr_to_ds, cr_to_h, cr_to_rp,
                                # Vsettan-only begin  Append dc_to_df
                                rp_to_rp, h_to_vm, rp_to_vm, dc_to_df])
                                # Vsettan-only end
    return traversal_spec


def build_property_spec(client_factory, type="VirtualMachine",
                        properties_to_collect=None,
                        all_properties=False):
    """Builds the Property Spec."""
    if not properties_to_collect:
        properties_to_collect = ["name"]

    property_spec = client_factory.create('ns0:PropertySpec')
    property_spec.all = all_properties
    property_spec.pathSet = properties_to_collect
    property_spec.type = type
    return property_spec


def build_object_spec(client_factory, root_folder, traversal_specs,
                      #Vsettan Resource Pool BEGIN
                      skip=False):
                      #Vsettan Resource Pool END
    """Builds the object Spec."""
    object_spec = client_factory.create('ns0:ObjectSpec')
    object_spec.obj = root_folder
    #Vsettan Resource Pool BEGIN
    object_spec.skip = skip
    #Vsettan Resource Pool END
    object_spec.selectSet = traversal_specs
    return object_spec


def build_property_filter_spec(client_factory, property_specs, object_specs):
    """Builds the Property Filter Spec."""
    property_filter_spec = client_factory.create('ns0:PropertyFilterSpec')
    property_filter_spec.propSet = property_specs
    property_filter_spec.objectSet = object_specs
    return property_filter_spec


def build_recursive_resource_pool_traversal_spec(client_factory):
    """Builds a Recursive Traversal Spec to traverse the object managed
    object hierarchy, starting from a ResourcePool and going to
    VirtualMachines via root and child ResourcePools
    """

    rp_to_rp_select_spec = build_selection_spec(client_factory, "rp_to_rp")
    rp_to_vm_select_spec = build_selection_spec(client_factory, "rp_to_vm")

     # For getting to Virtual Machine from the Resource Pool
    rp_to_vm = build_traversal_spec(client_factory, "rp_to_vm", "ResourcePool",
                                "vm", False,
                                [rp_to_rp_select_spec, rp_to_vm_select_spec])

    # For getting to child res pool from the parent res pool
    rp_to_rp = build_traversal_spec(client_factory, "rp_to_rp", "ResourcePool",
                                "resourcePool", False,
                                [rp_to_rp_select_spec, rp_to_vm_select_spec])

    return [rp_to_rp, rp_to_vm]

def build_recursive_cluster_traversal_spec(client_factory):
    """Builds a Recursive Traversal Spec to traverse the object managed
    object hierarchy, starting from a ClusterComputeResource and going to
    VirtualMachines via root and child ResourcePools
    """

    # For getting to resource pool from Compute Resource
    cr_to_rp = build_traversal_spec(client_factory, "cr_to_rp",
                                "ClusterComputeResource", "resourcePool", False,
                                build_recursive_resource_pool_traversal_spec(client_factory))

    return [cr_to_rp]

def get_objects_from_cluster(vim, type, cluster, properties_to_collect=None, all=False):
    """Gets the list of objects of the type specified."""
    if not properties_to_collect:
        properties_to_collect = ["name"]

    client_factory = vim.client.factory
    object_spec = build_object_spec(client_factory,
                        cluster,
                        build_recursive_cluster_traversal_spec(client_factory))
    property_spec = build_property_spec(client_factory, type=type,
                                properties_to_collect=properties_to_collect,
                                all_properties=all)
    property_filter_spec = build_property_filter_spec(client_factory,
                                [property_spec],
                                [object_spec])
    options = client_factory.create('ns0:RetrieveOptions')
    options.maxObjects = CONF.vmware.maximum_objects
    return vim.RetrievePropertiesEx(
            vim.service_content.propertyCollector,
            specSet=[property_filter_spec], options=options)

def get_objects_from_resource_pool(vim, type, resource_pool, properties_to_collect=None, all=False):
    """Gets the list of objects of the type specified."""
    if not properties_to_collect:
        properties_to_collect = ["name"]

    client_factory = vim.client.factory
    object_spec = build_object_spec(client_factory,
                        resource_pool,
                        build_recursive_resource_pool_traversal_spec(client_factory))
    property_spec = build_property_spec(client_factory, type=type,
                                properties_to_collect=properties_to_collect,
                                all_properties=all)
    property_filter_spec = build_property_filter_spec(client_factory,
                                [property_spec],
                                [object_spec])
    options = client_factory.create('ns0:RetrieveOptions')
    options.maxObjects = CONF.vmware.maximum_objects
    return vim.RetrievePropertiesEx(
            vim.service_content.propertyCollector,
            specSet=[property_filter_spec], options=options)

def get_contained_objects(vim, mobj, nested_type, recursive=True):
    """Gets the descendant Managed Objects of a Managed Entity."""
    client_factory = vim.client.factory
    collector = vim.service_content.propertyCollector
    view_mgr = vim.service_content.viewManager
    container_view = vim.CreateContainerView(view_mgr, container=mobj,
                                             type=[nested_type],
                                             recursive=recursive)

    # Create a filter spec for the requested properties
    property_spec = build_property_spec(client_factory, type=nested_type,
                                        properties_to_collect=["name"],
                                        all_properties=False)

    # Traversal spec determines the object traversal path to search for the
    # specified property. The following is the default for a container view
    traversal_spec = build_traversal_spec(client_factory, "view",
                                          "ContainerView", "view", False, None)

    # Create an object spec with the traversal spec
    object_spec = build_object_spec(client_factory, container_view,
                                    [traversal_spec], True)

    # Create a property filter spec with the property spec & object spec
    property_filter_spec = client_factory.create('ns0:PropertyFilterSpec')
    property_filter_spec.propSet = [property_spec]
    property_filter_spec.objectSet = [object_spec]
    options = client_factory.create('ns0:RetrieveOptions')
    options.maxObjects = CONF.vmware.maximum_objects
    return vim.RetrievePropertiesEx(collector, specSet=[property_filter_spec],
                                    options=options)
# Vsettan-only end
