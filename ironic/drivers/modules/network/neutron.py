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


from neutronclient.common import exceptions as neutron_exceptions
from oslo_config import cfg
from oslo_log import log
from oslo_utils import uuidutils

from ironic.common import exception
from ironic.common.i18n import _
from ironic.common.i18n import _LE
from ironic.common.i18n import _LI
from ironic.common import neutron
from ironic.drivers import base
from ironic import objects

LOG = log.getLogger(__name__)

CONF = cfg.CONF


class NeutronV2Network(base.NetworkInterface):
    """Neutron v2 network driver"""

    def __init__(self):
        failures = []
        cleaning_net = CONF.neutron.cleaning_network_uuid
        if not uuidutils.is_uuid_like(cleaning_net):
            failures.append('cleaning_network_uuid=%s' % cleaning_net)

        provisioning_net = CONF.neutron.provisioning_network_uuid
        if not uuidutils.is_uuid_like(provisioning_net):
            failures.append('provisioning_network_uuid=%s' % provisioning_net)

        if failures:
            raise exception.DriverLoadError(
                driver=self.__class__.__name__,
                reason=(_('The following [neutron] group config options have '
                          'incorrect values, they are required for this '
                          'network driver and must be UUIDs: %s') %
                        ', '.join(failures)))

    def add_provisioning_network(self, task):
        """Add the provisioning network to a node.

        :param task: A TaskManager instance.
        :raises: NetworkError
        """
        LOG.info(_LI('Adding provisioning network to node %s'),
                 task.node.uuid)
        neutron.add_ports_to_network(
            task, CONF.neutron.provisioning_network_uuid)

    def remove_provisioning_network(self, task):
        """Remove the provisioning network from a node.

        :param task: A TaskManager instance.
        :raises: NetworkError
        """
        neutron.remove_ports_from_network(
            task, CONF.neutron.provisioning_network_uuid)

        # Restoring the tenant vif to the ironic port.
        for item in task.ports:
            extra_dict = item.extra
            vif = extra_dict.pop('tenant_vif_port_id', None)
            if vif:
                extra_dict['vif_port_id'] = vif
                item.extra = extra_dict
                item.save()

    def add_cleaning_network(self, task):
        """Create neutron ports for each port on task.node to boot the ramdisk.

        :param task: a TaskManager instance.
        :raises: NetworkError
        :returns: a dictionary in the form {port.uuid: neutron_port['id']}
        """
        # If we have left over ports from a previous cleaning, remove them
        neutron.rollback_ports(task, CONF.neutron.cleaning_network_uuid)
        LOG.info(_LI('Adding cleaning network to node %s'), task.node.uuid)
        return neutron.add_ports_to_network(task,
                                            CONF.neutron.cleaning_network_uuid)

    def remove_cleaning_network(self, task):
        """Deletes the neutron port created for booting the ramdisk.

        :param task: a TaskManager instance.
        :raises: NetworkError
        """
        neutron.remove_ports_from_network(
            task, CONF.neutron.cleaning_network_uuid)

        for port in task.ports:
            extra_dict = port.extra
            extra_dict.pop('tenant_vif_port_id', None)
            extra_dict.pop('vif_port_id', None)
            port.extra = extra_dict
            port.save()

    def configure_tenant_networks(self, task):
        """Configure tenant networks for a node.

        :param task: A TaskManager instance.
        :raises: NetworkError
        """
        node = task.node
        LOG.info(_LI('Mapping instance ports to %s'), node.uuid)

        # TODO(russell_h): this is based on the broken assumption that the
        # number of Neutron ports will match the number of physical ports.
        # Instead, we should probably list ports for this instance in
        # Neutron and update all of those with the appropriate portmap.
        ports = objects.Port.list_by_node_id(task.context, node.id)
        if not ports:
            msg = _("No public network ports to activate attached to "
                    "node %s") % node.uuid
            LOG.error(msg)
            raise exception.NetworkError(msg)

        portmap = neutron.get_node_portmap(task)

        client = neutron.get_client()
        for port in ports:
            vif_port_id = port.extra.get('vif_port_id')

            if not vif_port_id:
                LOG.error(_LE('Node %(node)s port has no vif id in extra: '
                              '%(extra)s'),
                          {'extra': port.extra, 'node': node.uuid})
                continue

            LOG.debug('Mapping tenant port %(vif_port_id)s to node '
                      '%(node_id)s',
                      {'vif_port_id': vif_port_id, 'node_id': node.uuid})
            body = {
                'port': {
                    'device_owner': 'baremetal:none',
                    'device_id': node.instance_uuid or node.uuid,
                    'admin_state_up': True,
                    'binding:vnic_type': 'baremetal',
                    'binding:host_id': node.uuid,
                    'binding:profile': {
                        'local_link_information': [portmap[port.uuid]],
                    },
                }
            }

            try:
                client.update_port(vif_port_id, body)
            except neutron_exceptions.ConnectionFailed as e:
                msg = (_('Could not add public network VIF %(vif)s '
                         'to node %(node)s, possible network issue. %(exc)s') %
                       {'vif': vif_port_id,
                        'node': node.uuid,
                        'exc': e})
                LOG.error(msg)
                raise exception.NetworkError(msg)

    def unconfigure_tenant_networks(self, task):
        """Unconfigure tenant networks for a node.

        Nova takes care of port removal from tenant network, but we should
        remove it ourselves, so that ironic port could not be bound to tenant
        and cleaning network at the same time.

        :param task: A TaskManager instance.
        :raises: NetworkError
        """
        node = task.node
        LOG.info(_LI('Unmapping instance ports from node %s'), node.uuid)
        params = {'device_id': node.instance_uuid or node.uuid}

        neutron.remove_neutron_ports(params, node.uuid)
