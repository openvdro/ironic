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
Flat network driver. Useful for shared, flat networks.
"""

from oslo_config import cfg
from oslo_log import log
from oslo_utils import uuidutils

from ironic.common import exception
from ironic.common.i18n import _
from ironic.common.i18n import _LI
from ironic.common import neutron
from ironic.drivers import base


LOG = log.getLogger(__name__)

CONF = cfg.CONF


class FlatNetwork(base.NetworkInterface):
    """Flat network driver."""

    def __init__(self):
        cleaning_net = CONF.neutron.cleaning_network_uuid
        if not uuidutils.is_uuid_like(cleaning_net):
            raise exception.DriverLoadError(
                driver=self.__class__.__name__,
                reason=_('[neutron]/cleaning_network_uuid configuration is '
                         'required for this driver and must be a UUID'))

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
        # If we have left over ports from a previous cleaning, remove them
        neutron.rollback_ports(task, CONF.neutron.cleaning_network_uuid)
        LOG.info(_LI('Adding cleaning network to node %s'), task.node.uuid)
        return neutron.add_ports_to_network(
            task, CONF.neutron.cleaning_network_uuid, is_flat=True)

    def remove_cleaning_network(self, task):
        """Remove the cleaning network from a node.

        :param task: A TaskManager instance.
        """
        neutron.remove_ports_from_network(
            task, CONF.neutron.cleaning_network_uuid)

        for port in task.ports:
            extra_dict = port.extra
            extra_dict.pop('tenant_vif_port_id', None)
            extra_dict.pop('vif_port_id', None)
            port.extra = extra_dict
            port.save()
