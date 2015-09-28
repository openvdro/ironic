# Copyright 2015 Rackspace, Inc.
# All Rights Reserved
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
No-op network provider. Useful for shared, flat networks.
"""

from oslo_config import cfg
from oslo_log import log

from ironic.common import exception
from ironic.common.i18n import _
from ironic.common.i18n import _LI
from ironic.common import network
from ironic.networks import base


LOG = log.getLogger(__name__)
CONF = cfg.CONF


class NoopNetworkProvider(base.NetworkProvider):
    """No-op network provider."""

    def add_provisioning_network(self, task):
        """Add the provisioning network to a node.

        :param task: A TaskManager instance.
        """
        pass

    def remove_provisioning_network(self, task):
        """Remove the provisioning network from a node.

        :param task: A TaskManager instance.
        """
        pass

    def configure_tenant_networks(self, task):
        """Configure tenant networks for a node.

        :param task: A TaskManager instance.
        """
        pass

    def unconfigure_tenant_networks(self, task):
        """Unconfigure tenant networks for a node.

        :param task: A TaskManager instance.
        """
        pass

    def add_cleaning_network(self, task):
        """Add the cleaning network to a node.

        :param task: A TaskManager instance.
        :returns: a dictionary in the form {port.uuid: neutron_port['id']}
        """
        if not CONF.neutron.cleaning_network_uuid:
            raise exception.MissingParameterValue(_('Cleaning network '
                                                    'UUID not provided'))

        # If we have left over ports from a previous cleaning, remove them
        network.rollback_ports(task, CONF.neutron.cleaning_network_uuid)
        LOG.info(_LI('Adding cleaning network to node %s'), task.node.uuid)
        network.add_ports_to_network(task, CONF.neutron.cleaning_network_uuid,
                                     'cleaning_vif_port_id')

    def remove_cleaning_network(self, task):
        """Remove the cleaning network from a node.

        :param task: A TaskManager instance.
        """
        network.remove_ports_from_network(
            task, CONF.neutron.cleaning_network_uuid)

        for port in task.ports:
            extra_dict = port.extra
            extra_dict.pop('cleaning_vif_port_id', None)
            port.extra = extra_dict
            port.save()
