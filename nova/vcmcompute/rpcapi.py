# =================================================================
# Licensed Materials - Property of Vsettan
#
# (c) Copyright Vsettan Corp. All Rights Reserved
#
# =================================================================

from nova.compute import rpcapi

_compute_host = rpcapi._compute_host


class ComputeAPI(rpcapi.ComputeAPI):
    """VCM Compute API."""

    def __init__(self):
        super(ComputeAPI, self).__init__()

    def get_instance_snapshots(self, ctxt, instance):
        version = '4.0'
        cctxt = self.client.prepare(server=_compute_host(None, instance),
                version=version)
        return cctxt.call(ctxt, 'list_instance_snapshots',
                   instance=instance)

    def create_instance_snapshot(self, ctxt, instance, do_cast=False,
                                 snapshot_name=None, description=None,
                                 metadata=None):
        version = '4.0'
        cctxt = self.client.prepare(server=_compute_host(None, instance),
                version=version)
        # set timeout to two hours
        org_timeout = cctxt.timeout
        cctxt.timeout = 7200
        rpc_method = cctxt.cast if do_cast else cctxt.call
        try:
            result = rpc_method(ctxt, 'create_instance_snapshot',
                          instance=instance,
                          snapshot_name=snapshot_name,
                          description=description,
                          metadata=metadata)
        except Exception:
            raise
        finally:
            cctxt.timeout = org_timeout
        return result

    def delete_instance_snapshot(self, ctxt, instance, do_cast=False,
                                 snapshot_id=None):
        version = '4.0'
        cctxt = self.client.prepare(server=_compute_host(None, instance),
                version=version)
        rpc_method = cctxt.cast if do_cast else cctxt.call
        return rpc_method(ctxt, 'delete_instance_snapshot',
                          instance=instance,
                          snapshot_id=snapshot_id)

    def restore_instance_snapshot(self, ctxt, instance, do_cast=False,
                                  snapshot_id=None):
        version = '4.0'
        cctxt = self.client.prepare(server=_compute_host(None, instance),
                version=version)
        rpc_method = cctxt.cast if do_cast else cctxt.call
        return rpc_method(ctxt, 'restore_instance_snapshot',
                          instance=instance,
                          snapshot_id=snapshot_id)

    def get_datacenters(self, ctxt, host, do_cast=False):
        version = '4.0'
        cctxt = self.client.prepare(server=host, version=version)
        rpc_method = cctxt.cast if do_cast else cctxt.call
        return rpc_method(ctxt, 'get_datacenters')

    def get_datastores(self, ctxt, host, cluster_name=None, do_cast=False):
        version = '4.0'
        cctxt = self.client.prepare(server=host, version=version)
        rpc_method = cctxt.cast if do_cast else cctxt.call
        return rpc_method(ctxt, 'get_datastores', 
                          cluster_name=cluster_name)

    def get_virtual_adapter_network(self, ctxt, host, cluster_name=None, 
                                    do_cast=False):
        version = '4.0'
        cctxt = self.client.prepare(server=host, version=version)
        rpc_method = cctxt.cast if do_cast else cctxt.call
        return rpc_method(ctxt, 'get_virtual_adapter_network')

    def get_physical_adapter_network(self, ctxt, host, cluster_name=None, 
                                    do_cast=False):
        version = '4.0'
        cctxt = self.client.prepare(server=host, version=version)
        rpc_method = cctxt.cast if do_cast else cctxt.call
        return rpc_method(ctxt, 'get_physical_adapter_network')

