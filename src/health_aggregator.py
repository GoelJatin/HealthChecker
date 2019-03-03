# -*- coding: utf-8 -*-
"""
@author: Jatin Goel
"""

from threading import Thread

from exception import InvalidOperationException
from database.resource_model import Resource as DB_Resource
from resource_ops.resource import Resource as Client_Resource


class HealthAggregator:
    """Class to keep a check on the health of all the resources."""

    def __init__(self):
        self.resources = {}
        self.resource_state = {}
        self.synchronize()
        self.start()

    def _initialize(self, resource):
        """Initialize the Resource object for the given entity, and set its status."""
        self.resources[resource.hostname] = {
            'resource': Client_Resource(
                resource.hostname,
                resource.username,
                resource._decrypt_password(resource.password)
            ),
            'interval': resource.interval
        }

        self.resource_state[resource.hostname] = self.resources[resource.hostname].is_healthy()

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

    def worker(self, resource):
        """Worker block to process each resource.

            Args:
                resource    (str):  hostname of the resource to be processed

        """
        self.resource_state[resource] = self.resources[resource]['resource'].is_healthy()
        time.sleep(self.resources[resource]['interval'])

    def start(self):
        """Start thread for each resource to get the status."""
        for resource in self.resources:
            thread = Thread(target=self.worker, args=(resource), daemon=True)
            thread.start()

    def is_healthy(self):
        """Checks and returns if all resources are in a healthy state or not."""
        return all(self.resource_state.values())
