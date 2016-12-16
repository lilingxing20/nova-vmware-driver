# =================================================================
# Licensed Vsettan
#
# Copyright (c) 2016.11 Vsettan Corp. All Rights Reserved.
#
# author: lixx@vsettan.com.cn
#
# =================================================================

from nova.api.openstack import extensions
from nova.api.openstack import wsgi
from nova.i18n import _
from nova import exception
from nova import servicegroup
from nova import compute as compute
from nova import vcmcompute as vcmcompute
from oslo_log import log as logging

LOG = logging.getLogger(__name__)
ALIAS = "os-datacenter"
authorize = extensions.os_compute_authorizer(ALIAS)

class DatacenterController(wsgi.Controller):

    def __init__(self):
        super(DatacenterController, self).__init__()
        self.host_api = compute.HostAPI()
        self.servicegroup_api = servicegroup.API()
        self.vcmcompute_api = vcmcompute.API()

    def get_compute_nodes_of_vcenter(self, context):
        ''' Get compute nodes which as backend of vcenter server '''
        compute_nodes = self.host_api.compute_node_get_all(context)
        nodes={}
        for hyp in compute_nodes:
            if hyp.hypervisor_type == 'VMware vCenter Server':
                service = self.host_api.service_get_by_compute_host(context, hyp.host)
                active = self.servicegroup_api.service_is_up(service)
                if active:
                    nodes[hyp.hypervisor_hostname] = hyp.host
        return nodes.values()


    @extensions.expected_errors(())
    def index(self, req):
        """ Get all node datacenter. """
        context = req.environ['nova.context']
        authorize(context)
        nodes = self.get_compute_nodes_of_vcenter(context)
        all_node_dcs = {}
        for node in nodes:
            datacenter = self.vcmcompute_api.get_datacenters(context, node)
            all_node_dcs[node] = datacenter
        return all_node_dcs


    @extensions.expected_errors(())
    def detail(self, req, id=None):
        context = req.environ['nova.context']
        authorize(context)
        nodes = self.get_compute_nodes_of_vcenter(context)
        all_node_res_infos = {}
        for node in nodes:
            if id is None:
                res_infos = self.vcmcompute_api.get_datacenters(context, node, detail=True)
            elif id == 'datastores':
                res_infos = self.vcmcompute_api.get_datastores(context, node, detail=True)
            elif id == 'datastore_clusters':
                res_infos = self.vcmcompute_api.get_datastore_clusters(context, node, detail=True)
            elif id == 'hosts':
                res_infos = self.vcmcompute_api.get_esxi_hosts(context, node, detail=True)
            else:
                res_infos = {'help': {'datacenter': '/detail',
                             'datastore': 'datastores/datail',
                             'datastore_cluster': 'datastore_clusters/datail',
                             'esxi': 'hosts/datail',
                             }}
            all_node_res_infos[node] = res_infos
        return all_node_res_infos


    @extensions.expected_errors(())
    def datastores(self, req):
        """ Get all node datastores. """
        context = req.environ['nova.context']
        authorize(context)
        nodes = self.get_compute_nodes_of_vcenter(context)
        all_node_dss = {} 
        for node in nodes:
            datastores = self.vcmcompute_api.get_datastores(context, node)
            all_node_dss[node] = datastores
        return all_node_dss


    @extensions.expected_errors(())
    def datastore_clusters(self, req):
        """ Get datastore clusters for vCenter. """
        context = req.environ['nova.context']
        authorize(context)
        nodes = self.get_compute_nodes_of_vcenter(context)
        all_node_ds_clusters = {} 
        for node in nodes:
            ds_clusters = self.vcmcompute_api.get_datastore_clusters(context, node)
            all_node_ds_clusters[node] = ds_clusters
        return all_node_ds_clusters


    @extensions.expected_errors(())
    def hosts(self, req):
        """ Get esxi hosts for vCenter cluster. """
        context = req.environ['nova.context']
        authorize(context)
        nodes = self.get_compute_nodes_of_vcenter(context)
        all_node_esxi_hosts = {} 
        for node in nodes:
            esxi_hosts = self.vcmcompute_api.get_esxi_hosts(context, node)
            all_node_esxi_hosts[node] = esxi_hosts
        return all_node_esxi_hosts


    @extensions.expected_errors(())
    def vnc_port_state(self, req, id=None):
        """ Get vnc port for vCenter cluster. """
        context = req.environ['nova.context']
        authorize(context)
        nodes = self.get_compute_nodes_of_vcenter(context)
        vnc_port = None
        if id is None or id in ['allocated', 'available']:
            vnc_port = self.vcmcompute_api.get_vnc_port_state(context, nodes[0], req_type=id)
        return vnc_port


    @extensions.expected_errors(())
    def vm_network(self, req):
        """ Get all node vm networks. """
        context = req.environ['nova.context']
        authorize(context)
        nodes = self.get_compute_nodes_of_vcenter(context)
        all_vm_nets={} 
        for node in nodes:
            net = self.vcmcompute_api.get_virtual_adapter_network(context, node)
            all_vm_nets[node] = net
        return all_vm_nets


    @extensions.expected_errors(())
    def phy_network(self, req):
        """ Get all node physical networks. """
        context = req.environ['nova.context']
        authorize(context)
        nodes = self.get_compute_nodes_of_vcenter(context)
        all_phy_nets={} 
        for node in nodes:
            net = self.vcmcompute_api.get_physical_adapter_network(context, node)
            all_phy_nets[node] = net
        return all_phy_nets


    @extensions.expected_errors((404, 501))
    def uptime(self, req, id):
        context = req.environ['nova.context']
        print 'uptime' * 100
        print "id: %s \n" % id

    
class Datacenters(extensions.V21APIExtensionBase):

    name = "datacenter"
    alias = ALIAS
    updated = "2016-11-22T00:00:00+00:00"
    version = 1

    def get_resources(self):
        resources = [extensions.ResourceExtension(ALIAS,
                DatacenterController(),
                collection_actions={'datastores': 'GET',
                                    'datastore_clusters': 'GET',
                                    'hosts': 'GET',
                                    'vm_network': 'GET',
                                    'phy_network': 'GET',
                                    'vnc_port_state': 'GET',
                                    'detail': 'GET'
                                    },
                member_actions={'uptime': 'GET',
                                'vnc_port_state': 'GET',
                                'detail': 'GET'
                                }
                )]
        return resources

    def get_controller_extensions(self):
        return []

