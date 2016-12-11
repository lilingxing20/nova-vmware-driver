# =================================================================
# Licensed Materials - Property of Vsettan
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
from nova import vcmcompute as compute
from oslo_log import log as logging

LOG = logging.getLogger(__name__)
ALIAS = "os-server-snapshot"
authorize = extensions.extension_authorizer('compute', ALIAS)

def _translate_server_snapshot_view(server_snapshot, instance):
    result = {
        'snapshot_id': server_snapshot['snapshot_id'],

        'name': server_snapshot['name'],
        'description': server_snapshot['description'],
        'create_time': server_snapshot['create_time'],
        'is_current_snapshot': server_snapshot['is_current_snapshot'],
    }
    try:
        result['instance_uuid'] = server_snapshot['instance_uuid']
    except Exception:
        result['instance_uuid'] = instance['uuid']

    if server_snapshot['metadata']:
        result['metadata'] = server_snapshot['metadata']
    else:
        result['metadata'] = {}

    return {'server_snapshot': result}


def _translate_server_snapshots_view(server_snapshots, instance):
    return {'server_snapshots': [_translate_server_snapshot_view(
                                snapshot, instance)['server_snapshot']
                                 for snapshot in server_snapshots]}


class ServerSnapshotActionController(wsgi.Controller):
    def __init__(self, *args, **kwargs):
        super(ServerSnapshotActionController, self).__init__(*args, **kwargs)
        self.compute_api = compute.API()

    @wsgi.response(200)
    @wsgi.action('os-listServerSnapshot')
    def listServerSnapshot(self, req, id, body):
        """Return a list of snapshots of server."""
        context = req.environ['nova.context']
        authorize(context)

        instance = common.get_instance(self.compute_api, context, id, False)
        server_snapshots = self.compute_api.get_instance_snapshots(context,
                                                                   instance)

        return _translate_server_snapshots_view(server_snapshots, instance)

    @wsgi.response(202)
    @wsgi.action('os-createServerSnapshot')
    def createServerSnapshot(self, req, id, body):
        """Create a new snapshot."""
        context = req.environ['nova.context']
        authorize(context)

        snapshot_dict = body.get('os-createServerSnapshot', {})

        if type(snapshot_dict) is not dict or (
                'snapshot_name' not in snapshot_dict):
            msg = _("Server snapshot name is not defined")
            raise exc.HTTPBadRequest(explanation=msg)

        instance = common.get_instance(self.compute_api, context, id, False)
        description = snapshot_dict.get('description', '')
        metadata = snapshot_dict.get('metadata', {})
        if type(metadata) is not dict:
            msg = _("Invalid metadata.")
            raise exc.HTTPBadRequest(explanation=msg)

        snapshot_name = snapshot_dict.get('snapshot_name')
        snapshot = self.compute_api.create_instance_snapshot(context,
                                                  instance,
                                                  snapshot_name=snapshot_name,
                                                  description=description,
                                                  metadata=metadata)

        return _translate_server_snapshot_view(snapshot, instance)

    @wsgi.action('os-deleteServerSnapshot')
    def deleteServerSnapshot(self, req, id, body):
        """Delete the specified snapshot of instance."""
        context = req.environ['nova.context']
        authorize(context)
        snapshot_dict = body.get('os-deleteServerSnapshot', {})
        if type(snapshot_dict) is not dict or (
                'snapshot_id' not in snapshot_dict):
            msg = _("Server snapshot id is not defined")
            raise exc.HTTPBadRequest(explanation=msg)
        else:
            snapshot_id = snapshot_dict.get('snapshot_id')

        instance = common.get_instance(self.compute_api, context, id, False)

        self.compute_api.delete_instance_snapshot(context,
                                                  instance,
                                                  snapshot_id=snapshot_id)

        return webob.Response(status_int=202)

    @wsgi.action('os-restoreServerSnapshot')
    def restoreServerSnapshot(self, req, id, body):
        """Restore instance to a specified snapshot.

        If does not provide the snapshot id, it will be
        restore to the current snapshot.
        """
        context = req.environ['nova.context']
        authorize(context)

        instance = common.get_instance(self.compute_api, context, id, False)

        snapshot_dict = body.get('os-restoreServerSnapshot', {})
        snapshot_id = None
        if type(snapshot_dict) is not dict or (
                'snapshot_id' not in snapshot_dict):
            LOG.debug('snapshot id does not provided, will restore to the'
                        'current snapshot', instance=instance)
        else:
            snapshot_id = snapshot_dict.get('snapshot_id')

        self.compute_api.restore_instance_snapshot(context,
                                                  instance,
                                                  snapshot_id=snapshot_id)

        return webob.Response(status_int=202)


class ServerSnapshot(extensions.V21APIExtensionBase):
    """Server snapshot support."""

    name = "ServerSnapshot"
    alias = ALIAS
    namespace = "http://docs.openstack.org/compute/ext/server_snapshot/api/v2"
    updated = "2016-11-01T00:00:00+00:00"
    version = 1

    def get_controller_extensions(self):
        controller = ServerSnapshotActionController()
        extension = extensions.ControllerExtension(self, 'servers', controller)
        return [extension]

    def get_resources(self):
        return []

