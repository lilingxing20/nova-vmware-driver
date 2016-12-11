# =================================================================
# Licensed Materials - Property of Vsettan
#
# (c) Copyright Vsettan Corp. All Rights Reserved
#
# =================================================================

import inspect

from oslo_log import log as logging

from nova.compute import manager
from nova.compute import power_state
from nova import exception
from nova.i18n import _LE
from nova.vcmcompute import task_states

LOG = logging.getLogger(__name__)

wrap_exception = manager.wrap_exception


class VCMComputeManager(manager.ComputeManager):
    """VCM Compute Manager."""
    def __init__(self, compute_driver=None, *args, **kwargs):
        super(VCMComputeManager, self).__init__(compute_driver=compute_driver,
                                                *args, **kwargs)
        self._power_state_cache = None

    def _get_power_state(self, context, instance):
        # Get instance power state from cache when init instances
        upper_frame = inspect.currentframe().f_back
        caller = upper_frame.f_locals.get('self').__class__.__name__
        method = upper_frame.f_code.co_name
        if (caller == 'VCMComputeManager' and
            method == '_init_instance' and
            hasattr(self.driver, 'get_all_power_state')):
            # Get power state of all instances from hypervisor in one rpc call
            # Only support VCM Vmware driver
            if not self._power_state_cache:
                self._power_state_cache = self.driver.get_all_power_state()
            return (self._power_state_cache.get(instance.uuid) or
                    power_state.NOSTATE)
        return super(VCMComputeManager, self)._get_power_state(context,
                                                               instance)

    def _query_driver_power_state_and_sync(self, context, db_instance):
        # Skip sync discovered VM power state, leave it to discovery module
        if (hasattr(db_instance, 'metadata') and db_instance.metadata and
            db_instance.metadata.get('belong_to_compute')):
            return
        super(VCMComputeManager, self). \
            _query_driver_power_state_and_sync(context, db_instance)

    def finish_resize(self, context, disk_info, image, instance,
                      reservations, migration):
        super(VCMComputeManager, self).finish_resize(context, disk_info, image,
                                                     instance,
                                                     reservations, migration)
        # Auto-confirm hot resize
        if instance.system_metadata.get('vcm_hot_resize') is True:
            instance.system_metadata.pop('vcm_hot_resize')
            try:
                self.compute_api.confirm_resize(context, instance,
                                                migration=migration)
            except Exception as e:
                LOG.error(_LE("Fail to confirm hot resize: %s"),
                              e, instance=instance)

    @wrap_exception()
    def list_instance_snapshots(self, context, instance):
        """Get all the snapshots of instance on this host.

        :param context: security context
        :param instance: a nova.objects.instance.Instance object
        """
        return self.driver.list_instance_snapshots(context, instance)

    @wrap_exception()
    def create_instance_snapshot(self, context, instance, snapshot_name,
                                 description, metadata):
        """Create the snapshot of instance on this host.

        :param context: security context
        :param instance: a nova.objects.instance.Instance object
        """
        try:
            instance.task_state = task_states.SERVER_SNAPSHOT_CREATING
            instance.save(
                expected_task_state=task_states.SERVER_SNAPSHOT_CREATE_PENDING)
        except exception.InstanceNotFound:
            # possibility instance no longer exists, no point in continuing
            LOG.debug("Instance not found, could not set state %s "
                      "for instance.",
                      task_states.SERVER_SNAPSHOT_CREATING, instance=instance)
            return

        except exception.UnexpectedDeletingTaskStateError:
            LOG.debug("Instance being deleted, snapshot cannot continue",
                      instance=instance)
            raise

        snapshot = None
        try:
            snapshot = self.driver.create_instance_snapshot(context, instance,
                snapshot_name=snapshot_name, description=description,
                metadata=metadata)
        except (exception.InstanceNotFound,
                exception.UnexpectedDeletingTaskStateError):
            # the instance got deleted during the snapshot
            # Quickly bail out of here
            msg = "Instance disappeared during snapshot"
            LOG.debug(msg, instance=instance)
            raise
        except Exception:
            msg = "Got exception when create instance snapshot"
            LOG.warn(msg, instance=instance)
            raise
        finally:
            instance.task_state = None
            instance.save()

        return snapshot

    @wrap_exception()
    def delete_instance_snapshot(self, context, instance, snapshot_id):
        """Delete the snapshot of instance on this host.

        :param context: security context
        :param instance: a nova.objects.instance.Instance object
        :param snapshot_id: the snapshot id
        """
        try:
            instance.task_state = task_states.SERVER_SNAPSHOT_DELETING
            instance.save(
                expected_task_state=task_states.SERVER_SNAPSHOT_DELETE_PENDING)
        except exception.InstanceNotFound:
            # possibility instance no longer exists, no point in continuing
            LOG.debug("Instance not found, could not set state %s "
                      "for instance.",
                      task_states.SERVER_SNAPSHOT_DELETING, instance=instance)
            return

        except exception.UnexpectedDeletingTaskStateError:
            LOG.debug("Instance being deleted, snapshot cannot continue",
                      instance=instance)
            raise
        try:
            return self.driver.delete_instance_snapshot(context, instance,
                                                        snapshot_id)
        except (exception.InstanceNotFound,
                exception.UnexpectedDeletingTaskStateError):
            # the instance got deleted during the snapshot
            # Quickly bail out of here
            msg = "Instance disappeared during snapshot"
            LOG.debug(msg, instance=instance)
            raise
        except Exception:
            msg = "Got exception when delete instance snapshot"
            LOG.warn(msg, instance=instance)
            raise
        finally:
            instance.task_state = None
            instance.save()

    @wrap_exception()
    def restore_instance_snapshot(self, context, instance, snapshot_id=None):
        """Restore to the specified snapshot on this host.

        :param context: security context
        :param instance: a nova.objects.instance.Instance object
        :param snapshot_id: the snapshot id
        """
        try:
            instance.task_state = task_states.SERVER_SNAPSHOT_RESTORING
            instance.save(expected_task_state=
                          task_states.SERVER_SNAPSHOT_RESTORE_PENDING)
        except exception.InstanceNotFound:
            # possibility instance no longer exists, no point in continuing
            LOG.debug("Instance not found, could not set state %s "
                      "for instance.",
                      task_states.SERVER_SNAPSHOT_RESTORING,
                      instance=instance)
            return

        except exception.UnexpectedDeletingTaskStateError:
            LOG.debug("Instance being deleted, snapshot cannot continue",
                      instance=instance)
            raise
        try:
            return self.driver.restore_instance_snapshot(context, instance,
                                                         snapshot_id)
        except (exception.InstanceNotFound,
                exception.UnexpectedDeletingTaskStateError):
            # the instance got deleted during the snapshot
            # Quickly bail out of here
            msg = "Instance disappeared during snapshot"
            LOG.debug(msg, instance=instance)
            raise
        except Exception:
            msg = "Got exception when restore instance snapshot"
            LOG.warn(msg, instance=instance)
            raise
        finally:
            instance.task_state = None
            instance.save()

    @wrap_exception()
    def get_datacenters(self, context):
        try:
            return self.driver.get_datacenters(context)
        except Exception:
            msg = "Got exception when get datacenters"
            LOG.warn(msg)
            raise

    @wrap_exception()
    def get_datastores(self, context, cluster_name):
        try:
            return self.driver.get_datastores(context, cluster_name)
        except Exception:
            msg = "Got exception when get datastores"
            LOG.warn(msg)
            raise

    @wrap_exception()
    def get_virtual_adapter_network(self, context):
        try:
            return self.driver.get_virtual_adapter_network(context)
        except Exception:
            msg = "Got exception when get virtual adapter networks"
            LOG.warn(msg)
            raise

    @wrap_exception()
    def get_physical_adapter_network(self, context):
        try:
            return self.driver.get_physical_adapter_network(context)
        except Exception:
            msg = "Got exception when get physical adapter networks"
            LOG.warn(msg)
            raise


