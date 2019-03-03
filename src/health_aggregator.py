# -*- coding: utf-8 -*-
"""
@author: Jatin Goel
"""

import time

from threading import Thread

from exception import InvalidOperationException
from database.resource_model import Resource as DB_Resource
from resource_ops.resource import Resource as Client_Resource
from resource_ops.unix_resource import UnixResource


class HealthAggregator:
    """Class to keep a check on the health of all the resources."""

    def __init__(self):
        self.resources = {}
        self.resource_state = {}
        self.synchronize()
        self.start()

    def _initialize(self, resource):
        """Initialize the Resource object for the given entity, and set its status."""
        try:
            self.resources[resource.hostname] = {
                'resource': Client_Resource(
                    resource.hostname,
                    resource.username,
                    resource._decrypt_password(resource.password)
                ),
                'interval': resource.interval
            }

            self.resource_state[resource.hostname] = self.resources[resource.hostname]['resource'].is_healthy()
        except Exception:
            # in case the resource connection failed
            # since the resource is not added to the **resources** dict
            # it shall be tried again during syncronize
            self.resource_state[resource.hostname] = False

    def synchronize(self, operation='add'):
        """Synchronize the list of active resources and their status."""

        if operation.lower() == 'add':
            for resource in DB_Resource.get_all_resources():
                if resource.hostname not in self.resources:
                    self._initialize(resource)

        elif operation.lower() == 'delete':
            all_resources_hostnames = [resource.hostname for resource in DB_Resource.get_all_resources()]

            for resource in self.resources:
                if resource not in all_resources_hostnames:
                    del self.resources[resource]
                    del self.resource_state[resource]

        else:
            raise InvalidOperationException()

    def start(self):
        """Start thread for each resource to get the status."""
        for resource in self.resources:
            thread = Thread(target=worker, args=(self, resource,), daemon=True)
            thread.start()
            # self.worker(resource)

    def is_healthy(self):
        """Checks and returns if all resources are in a healthy state or not."""
        return all(self.resource_state.values())

    def cleanup(self):
        """Disconnect from all the resources."""
        for resource in self.resources:
            self.resources[resource]['resource'].disconnect()

        del self.resources
        del self.resource_state


def worker(cls_object, resource):
    """Worker block to process each resource.

        Args:
            cls_object  (object):   instance of the HealthAggregator class

            resource    (str):      hostname of the resource to be processed

    """
    while True:
        synchronize = False

        try:
            health = cls_object.resources[resource]['resource'].is_healthy()
            cls_object.resource_state[resource] = health

            interval = cls_object.resources[resource]['interval']

            if health is False and isinstance(cls_object.resources[resource]['resource'], UnixResource):
                # in case of UNIX machine, SSH tunnel is closed
                # hence we need to delete this object, and create new connection
                del cls_object.resources[resource]
                synchronize = True
        except KeyError:
            cls_object.resource_state[resource] = False
            synchronize = True

        if synchronize:
            cls_object.synchronize()

        time.sleep(interval)
