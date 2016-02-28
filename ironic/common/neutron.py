# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from neutronclient.common import exceptions as neutron_exceptions
from neutronclient.v2_0 import client as clientv20
from oslo_config import cfg
from oslo_log import log

from ironic.common import exception
from ironic.common.i18n import _
from ironic.common.i18n import _LE
from ironic.common.i18n import _LW
from ironic.common import keystone
from ironic import objects


LOG = log.getLogger(__name__)

CONF = cfg.CONF
CONF.import_opt('my_ip', 'ironic.netconf')

neutron_opts = [
    cfg.StrOpt('url',
               default='http://$my_ip:9696',
               help=_('URL for connecting to neutron.')),
    cfg.IntOpt('url_timeout',
               default=30,
               help=_('Timeout value for connecting to neutron in seconds.')),
    cfg.IntOpt('retries',
               default=3,
               help=_('Client retries in the case of a failed request.')),
    cfg.StrOpt('auth_strategy',
               default='keystone',
               choices=['keystone', 'noauth'],
               help=_('Default authentication strategy to use when connecting '
                      'to neutron. Can be either "keystone" or "noauth". '
                      'Running neutron in noauth mode (related to but not '
                      'affected by this setting) is insecure and should only '
                      'be used for testing.')),
    cfg.StrOpt('cleaning_network_uuid',
               help=_('Neutron network UUID for the ramdisk to be booted '
                      'into for cleaning nodes. Required for flat and '
                      'neutron network drivers.')),
    cfg.StrOpt('provisioning_network_uuid',
               help=_('Neutron network UUID for the ramdisk to be booted '
                      'into for provisioning nodes. Required for neutron '
                      'network drivers.')),
]

CONF.register_opts(neutron_opts, group='neutron')


def get_client(token=None):
    """Utility function to create Neutron client."""
    params = {
        'timeout': CONF.neutron.url_timeout,
        'retries': CONF.neutron.retries,
        'insecure': CONF.keystone_authtoken.insecure,
        'ca_cert': CONF.keystone_authtoken.certfile,
    }

    if CONF.neutron.auth_strategy == 'noauth':
        params['endpoint_url'] = CONF.neutron.url
        params['auth_strategy'] = 'noauth'
    elif (CONF.neutron.auth_strategy == 'keystone' and
          token is None):
        params['endpoint_url'] = (CONF.neutron.url or
                                  keystone.get_service_url('neutron'))
        params['username'] = CONF.keystone_authtoken.admin_user
        params['tenant_name'] = CONF.keystone_authtoken.admin_tenant_name
        params['password'] = CONF.keystone_authtoken.admin_password
        params['auth_url'] = (CONF.keystone_authtoken.auth_uri or '')
        if CONF.keystone.region_name:
            params['region_name'] = CONF.keystone.region_name
    else:
        params['token'] = token
        params['endpoint_url'] = CONF.neutron.url
        params['auth_strategy'] = None

    return clientv20.Client(**params)


def add_ports_to_network(task, network_uuid, is_flat=False):
    """Create Neutron ports for each port on task.node to boot the ramdisk.

    :param task: a TaskManager instance.
    :param network_uuid: UUID of a Neutron network where ports will be
        created.
    :param is_flat: Indicates whether it is a flat network or not.
    :raises: NetworkError
    :returns: a dictionary in the form {port.uuid: neutron_port['id']}
    """
    client = get_client()

    LOG.debug('Using %(net_iface)s network interface for node '
              '%(node)s.', {'net_iface': task.node.network_interface,
                            'node': task.node.uuid})
    body = {
        'port': {
            'network_id': network_uuid,
            'admin_state_up': True,
            'binding:vnic_type': 'baremetal',
            'device_owner': 'baremetal:none',
        }
    }

    if not is_flat:
        # NOTE(vdrok): It seems that change
        # I437290affd8eb87177d0626bf7935a165859cbdd to Neutron broke the
        # possibility to always bind port, it fails in case of flat network.
        body['port']['binding:host_id'] = task.node.uuid

    # Since instance_uuid will not be available during cleaning
    # operations, we need to check that and populate them only when
    # available
    body['port']['device_id'] = task.node.instance_uuid or task.node.uuid

    ports = {}
    failures = []
    portmap = get_node_portmap(task)
    for ironic_port in task.ports:
        body['port']['mac_address'] = ironic_port.address
        binding_profile = {'local_link_information':
                           [portmap[ironic_port.uuid]]}
        body['port']['binding:profile'] = binding_profile
        try:
            port = client.create_port(body)
        except neutron_exceptions.ConnectionFailed as e:
            rollback_ports(task, network_uuid)
            msg = (_('Could not create port on given network %(net)s '
                     'from %(node)s. %(exc)s') %
                   {'net': network_uuid, 'node': task.node.uuid, 'exc': e})
            LOG.exception(msg)
            raise exception.NetworkError(msg)

        extra_dict = ironic_port.extra
        # Backup existing vif
        vif = extra_dict.get('vif_port_id')
        # Setting provisioning port as the vif for the ironic port.
        try:
            extra_dict['vif_port_id'] = port['port']['id']
        except KeyError:
            failures.append(ironic_port.uuid)
        else:
            if vif:
                extra_dict['tenant_vif_port_id'] = vif
            ironic_port.extra = extra_dict
            ironic_port.save()
            # Match return value of get_node_vif_ids()
            ports[ironic_port.uuid] = port['port']['id']

    if failures:
        if len(failures) == len(task.ports):
            raise exception.NetworkError(_(
                "Failed to update vif_port_id for any port "
                "on node %s.") % task.node.uuid)
        else:
            LOG.warning(_LW("Some errors were encountered when updating "
                            "vif_port_id for node %(node)s on "
                            "the following ports: %(ports)s."),
                        {'node': task.node.uuid, 'ports': failures})
    return ports


def remove_ports_from_network(task, network_uuid):
    """Deletes the neutron port created for booting the ramdisk.

    :param task: a TaskManager instance.
    :param network_uuid: UUID of a Neutron network ports will be deleted from.
    :raises: NetworkError
    """
    macs = [p.address for p in task.ports]
    params = {
        'network_id': network_uuid,
        'mac_address': macs,
    }
    LOG.debug("Removing ports on network %(net)s on node %(node)s.",
              {'net': network_uuid, 'node': task.node.uuid})

    remove_neutron_ports(params, task.node.uuid)


def remove_neutron_ports(params, node_uuid):
    client = get_client()

    try:
        response = client.list_ports(**params)
    except neutron_exceptions.ConnectionFailed as e:
        msg = (_('Could not get given network vif for %(node)s '
                 'from Neutron, possible network issue. %(exc)s') %
               {'node': node_uuid, 'exc': e})
        LOG.exception(msg)
        raise exception.NetworkError(msg)

    ports = response.get('ports', [])
    if not ports:
        LOG.debug('No ports to remove for node %s', node_uuid)
        return

    for port in ports:
        if not port['id']:
            # TODO(morgabra) client.list_ports() sometimes returns
            # port objects with null ids. It's unclear why this happens.
            LOG.warning(_LW("Deleting neutron port failed, missing 'id'. "
                            "Node: %(node)s, neutron port: %(port)s."),
                        {'node': node_uuid, 'port': port})
            continue

        LOG.debug('Deleting neutron port %(vif_port_id)s of node '
                  '%(node_id)s.',
                  {'vif_port_id': port['id'], 'node_id': node_uuid})

        try:
            client.delete_port(port['id'])
        except neutron_exceptions.ConnectionFailed as e:
            msg = (_('Could not remove VIF %(vif)s of node %(node)s, possibly '
                     'a network issue: %(exc)s') %
                   {'vif': port['id'], 'node': node_uuid, 'exc': e})
            LOG.exception(msg)
            raise exception.NetworkError(msg)


def get_node_portmap(task):
    """Extract the switch port information for the node.

    :param task: a task containing the Node object.
    :returns: a dictionary in the form {port.uuid: port.local_link_connection}
    """
    node = task.node

    ports = objects.Port.list_by_node_id(task.context, node.id)
    portmap = {}
    for port in ports:
        portmap[port.uuid] = port.local_link_connection
    return portmap
    # TODO(jroll) raise InvalidParameterValue if a port doesn't have the
    # necessary info? (probably)


def rollback_ports(task, network_uuid):
    """Attempts to delete any ports created by cleaning/provisioning

    Purposefully will not raise any exceptions so error handling can
    continue.

    :param task: a TaskManager instance.
    :param network_uuid: UUID of a Neutron network.
    """
    try:
        remove_ports_from_network(task, network_uuid)
    except Exception:
        # Log the error, but let the caller invoke the
        # manager.cleaning_error_handler().
        LOG.exception(_LE(
            'Failed to rollback port changes for node %(node)s '
            'on network %(network)s'), {'node': task.node.uuid,
                                        'network': network_uuid})
