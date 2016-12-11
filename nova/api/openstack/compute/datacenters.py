# =================================================================
# Licensed Vsettan
#
# Copyright (c) 2016.11 Vsettan Corp. All Rights Reserved.
#
# author: lixx@vsettan.com.cn
#
# =================================================================

import webob
from webob import exc

from nova.api.openstack import common
from nova.api.openstack import extensions
from nova.api.openstack import wsgi
from nova.i18n import _
from nova import servicegroup
from nova import exception
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
        self.vcmcompute_api = vcmcompute.API()

    def get_vcenter_hosts(self, context):
        compute_nodes = self.host_api.compute_node_get_all(context)
        hosts=[]
        for hyp in compute_nodes:
            if hyp.hypervisor_type == 'VMware vCenter Server':
                hosts.append(hyp.host)
        return hosts


    @extensions.expected_errors(())
    def index(self, req):
        """ Get all node datacenter. """
        context = req.environ['nova.context']
        authorize(context)
        hosts = self.get_vcenter_hosts(context)
        all_node_dcs = {}
        for host in hosts:
            datacenter = self.vcmcompute_api.get_datacenters(context, host)
            all_node_dcs[host] = datacenter
        return all_node_dcs


    @extensions.expected_errors(())
    def datastores(self, req):
        """ Get all node datastores. """
        context = req.environ['nova.context']
        authorize(context)
        hosts = self.get_vcenter_hosts(context)
        all_node_dss={} 
        for host in hosts:
            datastores = self.vcmcompute_api.get_datastores(context, host)
            all_node_dss[host] = datastores
        return all_node_dss


    @extensions.expected_errors(())
    def vm_network(self, req):
        """ Get all node vm networks. """
        context = req.environ['nova.context']
        authorize(context)
        hosts = self.get_vcenter_hosts(context)
        all_vm_nets={} 
        for host in hosts:
            net = self.vcmcompute_api.get_virtual_adapter_network(context, host)
            all_vm_nets[host] = net
        return all_vm_nets


    @extensions.expected_errors(())
    def phy_network(self, req):
        """ Get all node physical networks. """
        context = req.environ['nova.context']
        authorize(context)
        hosts = self.get_vcenter_hosts(context)
        all_phy_nets={} 
        for host in hosts:
            net = self.vcmcompute_api.get_physical_adapter_network(context, host)
            all_phy_nets[host] = net
        return all_phy_nets


    @extensions.expected_errors(())
    def detail(self, req):
        context = req.environ['nova.context']
        authorize(context)
        print 'detail' * 100
        print "\n"

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
                                    'vm_network': 'GET',
                                    'phy_network': 'GET',
                                    'detail': 'GET'},
                member_actions={'uptime': 'GET'})]
        return resources

    def get_controller_extensions(self):
        return []

