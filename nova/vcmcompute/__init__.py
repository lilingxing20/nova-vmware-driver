# =================================================================
# Licensed Materials - Property of Vsettan
#
# (c) Copyright Vsettan Corp. All Rights Reserved
#
# =================================================================

from oslo_utils import importutils

import nova.cells.opts
import nova.exception


CELL_TYPE_TO_CLS_NAME = {'api': 'nova.compute.cells_api.ComputeCellsAPI',
                         'compute': 'nova.vcmcompute.api.API',
                         None: 'nova.vcmcompute.api.API',
                        }


def _get_compute_api_class_name():
    """Returns the name of compute API class."""
    cell_type = nova.cells.opts.get_cell_type()
    return CELL_TYPE_TO_CLS_NAME[cell_type]


def API(*args, **kwargs):
    class_name = _get_compute_api_class_name()
    return importutils.import_object(class_name, *args, **kwargs)


def HostAPI(*args, **kwargs):
    """Returns the 'HostAPI' class from the same module as the configured
    compute api
    """
    compute_api_class_name = _get_compute_api_class_name()
    compute_api_class = importutils.import_class(compute_api_class_name)
    class_name = compute_api_class.__module__ + ".HostAPI"
    return importutils.import_object(class_name, *args, **kwargs)


def InstanceActionAPI(*args, **kwargs):
    """Returns the 'InstanceActionAPI' class from the same module as the
    configured compute api.
    """
    compute_api_class_name = _get_compute_api_class_name()
    compute_api_class = importutils.import_class(compute_api_class_name)
    class_name = compute_api_class.__module__ + ".InstanceActionAPI"
    return importutils.import_object(class_name, *args, **kwargs)
