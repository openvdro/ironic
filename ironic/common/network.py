# Copyright 2014 Rackspace, Inc.
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
from neutronclient.v2_0 import client as clientv20
from oslo_config import cfg
from oslo_log import log
import stevedore

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
               help=_('UUID of the network to create Neutron ports on when '
                      'booting to a ramdisk for cleaning/zapping using '
                      'Neutron DHCP')),
    cfg.StrOpt('provisioning_network_uuid',
               help=_('UUID of the network to create Neutron ports on when '
                      'booting to a ramdisk for provisioning.'))

]


network_provider_opts = [
    cfg.StrOpt('network_provider',
               default='none',
               help=_('Network provider to use for switching to cleaning'
                      '/provisioning/tenant network while provisioning. '
                      '"neutron_plugin" uses Neutron and "none" '
                      'uses a no-op provider. Can be overridden on a per-node '
                      "basis via the node's network_provider attribute.")),
]


CONF.register_opts(neutron_opts, group='neutron')
CONF.register_opts(network_provider_opts)


def get_network_provider(network_provider=None):
    """Loads specified network provider.

    Load the specified network provider. If not specified, load the
    network provider specified in the ironic config.

    :param network_provider: Network provider name to load.
    :returns: Instance of the driver object.
    :raises: NetworkProviderNotFound
    """

    provider_name = network_provider or CONF.network_provider

    try:
        extension_manager = stevedore.driver.DriverManager(
            'ironic.network',
            provider_name,
            invoke_on_load=True)
    except RuntimeError:
        raise exception.NetworkProviderNotFound(provider_name=provider_name)

    # TODO(lazy_prince) Need to check for binding extensions loaded in neutron
    return extension_manager.driver


def get_neutron_client(token=None):
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


def get_node_vif_ids(task):
    """Get all VIF ids for a node.

    This function does not handle multi node operations.

    :param task: a TaskManager instance.
    :returns: A dict of Node's neutron ports where keys are
        'ports' & 'portgroups' and the values are dict of UUIDs
        and their associated VIFs, e.g.

              ::

               {'ports': {'port.uuid': vif.id},
                'portgroups': {'portgroup.uuid': vif.id}}
    """
    vifs = {}
    portgroup_vifs = {}
    port_vifs = {}
    for portgroup in task.portgroups:
        vif = portgroup.extra.get('vif_port_id')
        if vif:
            portgroup_vifs[portgroup.uuid] = vif
    vifs['portgroups'] = portgroup_vifs
    for port in task.ports:
        vif = port.extra.get('vif_port_id')
        if vif:
            port_vifs[port.uuid] = vif
    vifs['ports'] = port_vifs
    return vifs


def add_ports_to_network(task, network_uuid):
    """Create Neutron ports for each port on task.node to boot the ramdisk.

    :param task: a TaskManager instance.
    :raises: NetworkError
    :returns: a dictionary in the form {port.uuid: neutron_port['id']}
    """
    client = get_neutron_client()
    network_provider = task.node.network_provider or CONF.network_provider

    LOG.debug('Using network provider %(net_provider)s for node '
              '%(node)s', {'net_provider': network_provider,
                           'node': task.node.uuid})
    body = {
        'port': {
            'network_id': network_uuid,
            'admin_state_up': True,
            'binding:vnic_type': 'baremetal',
            'device_owner': 'baremetal:none',
            'binding:host_id': task.node.uuid,
        }
    }

    # Since instance_uuid will not be available during cleaning
    # operations, we need to check that and populate them only when
    # available
    if task.node.instance_uuid:
        body['port']['device_id'] = task.node.instance_uuid

    ports = {}
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

        if not port.get('port') or not port['port'].get('id'):
            rollback_ports(task, network_uuid)
            msg = (_('Failed to create port on given network %(net)s '
                     'from %(node)s.') %
                   {'net': network_uuid, 'node': task.node.uuid})
            LOG.error(msg)
            raise exception.NetworkError(msg)

        extra_dict = ironic_port.extra
        # Backup Existing vif.
        vif = extra_dict.pop('vif_port_id', None)
        if vif:
            extra_dict['tenant_vif_port_id'] = vif

        failures = []
        # Setting provisioning port as the vif for the ironic port.
        try:
            extra_dict['vif_port_id'] = port['port']['id']
        except KeyError:
            # This is an internal error in Ironic.  All DHCP providers
            # implementing create_cleaning_ports are supposed to
            # return a VIF port ID for all Ironic ports.  But
            # that doesn't seem to be true here.
            failures.append(vif)
        else:
            ironic_port.extra = extra_dict
            ironic_port.save()

        # Match return value of get_node_vif_ids()
        ports[ironic_port.uuid] = port['port']['id']

    if failures:
        if len(failures) == len(task.ports):
            raise exception.FailedToUpdateVIFPortIdOptOnPort(_(
                "Failed to update vif_port_id for any port "
                "on node %s.") % task.node.uuid)
        else:
            LOG.warning(_LW("Some errors were encountered when updating "
                            "vif_port_id for node %(node)s on "
                            "the following vifs: %(vifs)s."),
                        {'node': task.node.uuid, 'vifs': failures})
    return ports


def remove_ports_from_network(task, network_uuid):
    """Deletes the neutron port created for booting the ramdisk.

    :param task: a TaskManager instance.
    :raises: NetworkError
    """
    client = get_neutron_client()
    macs = [p.address for p in task.ports]
    params = {
        'network_id': network_uuid,
        'binding:host_id': task.node.uuid,
    }
    try:
        ports = client.list_ports(**params)
    except neutron_exceptions.ConnectionFailed as e:
        msg = (_('Could not get given network vif for %(node)s '
                 'from Neutron, possible network issue. %(exc)s') %
               {'node': task.node.uuid,
                'exc': e})
        LOG.exception(msg)
        raise exception.NetworkError(msg)

    # Iterate the list of Neutron port dicts, remove the ones we added
    for neutron_port in ports.get('ports', []):
        # Only delete ports using the node's mac addresses
        if neutron_port.get('mac_address') in macs:
            try:
                client.delete_port(neutron_port.get('id'))
            except neutron_exceptions.ConnectionFailed as e:
                msg = (_('Could not remove ports on given network '
                         '%(net)s from %(node)s, possible network issue. '
                         '%(exc)s') %
                       {'net': network_uuid,
                        'node': task.node.uuid,
                        'exc': e})
                LOG.exception(msg)
                raise exception.NetworkError(msg)


def get_node_portmap(task):
    """Extract the switch port information for the node.

    :param task: a task containing the Node object.
    :returns: a dictionary in the form {port.uuid: port.local_link_connection}
    :returns: a list describing the switch ports for the node.
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
