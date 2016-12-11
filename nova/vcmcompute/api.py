# =================================================================
# Licensed Materials - Property of Vsettan
#
# (c) Copyright Vsettan Corp. All Rights Reserved
#
# =================================================================

from nova.compute import api
from nova.vcmcompute import rpcapi as compute_rpcapi
from nova.vcmcompute import task_states

wrap_check_policy = api.wrap_check_policy

check_instance_cell = api.check_instance_cell


class API(api.API):
    """VCM Compute API."""

    def __init__(self, **kwargs):
        super(API, self).__init__(self, **kwargs)
        self.compute_rpcapi = compute_rpcapi.ComputeAPI()

    @wrap_check_policy
    @check_instance_cell
    def get_instance_snapshots(self, context, instance):
        return self.compute_rpcapi.get_instance_snapshots(context, instance)

    @wrap_check_policy
    @check_instance_cell
    def create_instance_snapshot(self, context, instance, do_cast=False,
                                 snapshot_name=None, description=None,
                                 metadata=None):
        instance.task_state = task_states.SERVER_SNAPSHOT_CREATE_PENDING
        instance.save(expected_task_state=[None])
        return self.compute_rpcapi.create_instance_snapshot(context,
            instance=instance,
            do_cast=do_cast,
            snapshot_name=snapshot_name,
            description=description,
            metadata=metadata)

    @wrap_check_policy
    @check_instance_cell
    def delete_instance_snapshot(self, context, instance, do_cast=False,
                                 snapshot_id=None):
        instance.task_state = task_states.SERVER_SNAPSHOT_DELETE_PENDING
        instance.save(expected_task_state=[None])
        return self.compute_rpcapi.delete_instance_snapshot(
            context, instance=instance, do_cast=do_cast,
            snapshot_id=snapshot_id)

    @wrap_check_policy
    @check_instance_cell
    def restore_instance_snapshot(self, context, instance, do_cast=False,
                                  snapshot_id=None):
        instance.task_state = task_states.SERVER_SNAPSHOT_RESTORE_PENDING
        instance.save(expected_task_state=[None])
        return self.compute_rpcapi.restore_instance_snapshot(
            context, instance=instance, do_cast=do_cast,
            snapshot_id=snapshot_id)


    @wrap_check_policy
    def get_datacenters(self, context, host, cluster_name=None):
        return self.compute_rpcapi.get_datacenters(context, host)

    @wrap_check_policy
    def get_datastores(self, context, host, cluster_name=None):
        return self.compute_rpcapi.get_datastores(context, host, cluster_name)

    @wrap_check_policy
    def get_virtual_adapter_network(self, context, host, cluster_name=None):
        return self.compute_rpcapi.get_virtual_adapter_network(context, host)

    @wrap_check_policy
    def get_physical_adapter_network(self, context, host, cluster_name=None):
        return self.compute_rpcapi.get_physical_adapter_network(context, host)

