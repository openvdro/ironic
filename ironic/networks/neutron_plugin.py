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

from ironic.common import exception
from ironic.common.i18n import _
from ironic.common.i18n import _LE
from ironic.common.i18n import _LW
from ironic.common.i18n import _LI
from ironic.common import network
from ironic.networks import base
from ironic import objects

LOG = log.getLogger(__name__)
CONF = cfg.CONF


def _list_ports(task):
    """List all ports for a node.

    :param task: a task containing the Node object.
    :returns: A list of all networks for `node`.
    """
    node = task.node
    client = network.get_neutron_client()

    params = {'device_id': node.instance_uuid}
    instance_ports = client.list_ports(**params).get('ports')

    return instance_ports


class NeutronV2NetworkProvider(base.NetworkProvider):
    """Neutron plugin network provider"""

    def add_provisioning_network(self, task):
        """Add the provisioning network to a node.

        :param task: A TaskManager instance.
        :raises: MissingParameterValue
        :raises: NetworkError
        :raises: FailedToUpdateVIFPortIdOptOnPort
        """
        if not CONF.neutron.provisioning_network_uuid:
            raise exception.MissingParameterValue(
                _('Valid provisioning network UUID not provided'))

        LOG.info(_LI('Adding provisioning network to node %s'),
                 task.node.uuid)
        network.add_ports_to_network(
            task, CONF.neutron.provisioning_network_uuid)

    def remove_provisioning_network(self, task):
        """Remove the provisioning network from a node.

        :param task: A TaskManager instance.
        """
        network.remove_ports_from_network(
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
        :raises: MissingParameterValue if the cleaning network is None
        :returns: a dictionary in the form {port.uuid: neutron_port['id']}
        """
        if not CONF.neutron.cleaning_network_uuid:
            raise exception.MissingParameterValue(_('Cleaning network '
                                                    'UUID not provided'))

        # If we have left over ports from a previous cleaning, remove them
        network.rollback_ports(task, CONF.neutron.cleaning_network_uuid)
        LOG.info(_LI('Adding cleaning network to node %s'), task.node.uuid)
        network.add_ports_to_network(task, CONF.neutron.cleaning_network_uuid)

    def remove_cleaning_network(self, task):
        """Deletes the neutron port created for booting the ramdisk.

        :param task: a TaskManager instance.
        :raises: NetworkError
        """
        network.remove_ports_from_network(
            task, CONF.neutron.cleaning_network_uuid)

        for port in task.ports:
            if 'vif_port_id' in port.extra:
                extra_dict = port.extra
                extra_dict.pop('vif_port_id', None)
                port.extra = extra_dict
                port.save()

    def configure_tenant_networks(self, task):
        """Configure tenant networks for a node.

        :param task: A TaskManager instance.
        :raises: NetworkError
        """
        node = task.node
        client = network.get_neutron_client()
        LOG.info(_LI('Mapping instance ports to %s'), node.uuid)

        portmap = network.get_node_portmap(task)
        if not portmap:
            raise exception.NoValidPortmaps(
                node=node.uuid, vif=CONF.neutron.provisioning_network_uuid)

        # TODO(russell_h): this is based on the broken assumption that the
        # number of Neutron ports will match the number of physical ports.
        # Instead, we should probably list ports for this this instance in
        # Neutron and update all of those with the appropriate portmap.
        ports = objects.Port.list_by_node_id(task.context, node.id)
        if not ports:
            raise exception.NetworkError(_LE(
                "No public network ports to activate attached to "
                "node %s") % node.uuid)

        for port in ports:
            vif_port_id = port.extra.get('vif_port_id')

            if not vif_port_id:
                LOG.error('Node %(node)s port has no vif id in extra:'
                          ' %(extra)s',
                          {'extra': port.extra, 'node': node.uuid})
                continue

            LOG.debug('Mapping tenant port %(vif_port_id)s to node '
                      '%(node_id)s',
                      {'vif_port_id': vif_port_id, 'node_id': node.id})
            body = {
                'port': {
                    'device_owner': 'baremetal:none',
                    'device_id': task.node.instance_uuid,
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
            except neutron_exceptions.ConnectionFailed:
                raise exception.NetworkError(_(
                    'Could not add public network %(vif)s '
                    'to %(node)s, possible network issue.') %
                    {'vif': vif_port_id,
                     'node': node.uuid})

    def unconfigure_tenant_networks(self, task):
        """Unconfigure tenant networks for a node.

        Nova takes care of port removal from tenant network, but we should
        unbind it, so that ironic port could not bound to tenant and cleaning
        network at the same time.

        :param task: A TaskManager instance.
        """
        node = task.node
        LOG.info(_LI('Unmapping instance ports from %s'), node.uuid)

        ports = _list_ports(task)
        if not ports:
            LOG.info(_LI('No tenant ports to deconfigure, skipping '
                         'deconfiguration for node %s'), node.uuid)
            return

        for port in ports:
            if not port['id']:
                # TODO(morgabra) client.list_ports() sometimes returns
                # port objects with null ids. It's unclear why this happens.
                LOG.warn(_LW("Unmapping port failed, missing 'id'. "
                             "Node: %(node)s Port: %(port)s"), {'node': node,
                                                                'port': port})
                continue

            LOG.debug('Unmapping instance port %(vif_port_id)s from node '
                      '%(node_id)s',
                      {'vif_port_id': port['id'], 'node_id': node.uuid})

            body = {
                'port': {
                    'device_owner': 'baremetal:none',
                    'device_id': task.node.instance_uuid,
                    'binding:vnic_type': 'baremetal',
                    'binding:host_id': node.uuid,
                    'binding:profile': {}
                }
            }
            try:
                client = network.get_neutron_client()
                client.update_port(port['id'], body)
            except neutron_exceptions.ConnectionFailed as e:
                raise exception.NetworkError(_(
                    'Could not remove tenant network %(vif)s from %(node)s, '
                    'possibly a network issue: %(exc)s') %
                    {'vif': port['id'],
                     'node': node.uuid,
                     'exc': e})
