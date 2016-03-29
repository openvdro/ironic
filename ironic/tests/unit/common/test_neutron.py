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

import mock
from neutronclient.common import exceptions as neutron_client_exc
from neutronclient.v2_0 import client
from oslo_config import cfg
from oslo_utils import uuidutils

from ironic.common import exception
from ironic.common import neutron
from ironic.conductor import task_manager
from ironic.tests import base
from ironic.tests.unit.conductor import mgr_utils
from ironic.tests.unit.db import base as db_base
from ironic.tests.unit.objects import utils as object_utils


class TestNeutronClient(base.TestCase):

    def setUp(self):
        super(TestNeutronClient, self).setUp()
        self.config(url='test-url',
                    url_timeout=30,
                    retries=2,
                    group='neutron')
        self.config(insecure=False,
                    certfile='test-file',
                    admin_user='test-admin-user',
                    admin_tenant_name='test-admin-tenant',
                    admin_password='test-admin-password',
                    auth_uri='test-auth-uri',
                    group='keystone_authtoken')

    @mock.patch.object(client.Client, "__init__")
    def test_get_neutron_client_with_token(self, mock_client_init):
        token = 'test-token-123'
        expected = {'timeout': 30,
                    'retries': 2,
                    'insecure': False,
                    'ca_cert': 'test-file',
                    'token': token,
                    'endpoint_url': 'test-url',
                    'auth_strategy': None}

        mock_client_init.return_value = None
        neutron.get_client(token=token)
        mock_client_init.assert_called_once_with(**expected)

    @mock.patch.object(client.Client, "__init__")
    def test_get_neutron_client_without_token(self, mock_client_init):
        expected = {'timeout': 30,
                    'retries': 2,
                    'insecure': False,
                    'ca_cert': 'test-file',
                    'endpoint_url': 'test-url',
                    'username': 'test-admin-user',
                    'tenant_name': 'test-admin-tenant',
                    'password': 'test-admin-password',
                    'auth_url': 'test-auth-uri'}

        mock_client_init.return_value = None
        neutron.get_client(token=None)
        mock_client_init.assert_called_once_with(**expected)

    @mock.patch.object(client.Client, "__init__")
    def test_get_neutron_client_with_region(self, mock_client_init):
        expected = {'timeout': 30,
                    'retries': 2,
                    'insecure': False,
                    'ca_cert': 'test-file',
                    'endpoint_url': 'test-url',
                    'username': 'test-admin-user',
                    'tenant_name': 'test-admin-tenant',
                    'password': 'test-admin-password',
                    'auth_url': 'test-auth-uri',
                    'region_name': 'test-region'}

        self.config(region_name='test-region',
                    group='keystone')
        mock_client_init.return_value = None
        neutron.get_client(token=None)
        mock_client_init.assert_called_once_with(**expected)

    @mock.patch.object(client.Client, "__init__")
    def test_get_neutron_client_noauth(self, mock_client_init):
        self.config(auth_strategy='noauth', group='neutron')
        expected = {'ca_cert': 'test-file',
                    'insecure': False,
                    'endpoint_url': 'test-url',
                    'timeout': 30,
                    'retries': 2,
                    'auth_strategy': 'noauth'}

        mock_client_init.return_value = None
        neutron.get_client(token=None)
        mock_client_init.assert_called_once_with(**expected)

    def test_out_range_auth_strategy(self):
        self.assertRaises(ValueError, cfg.CONF.set_override,
                          'auth_strategy', 'fake', 'neutron',
                          enforce_type=True)


class TestNeutronNetworkActions(db_base.DbTestCase):

    def setUp(self):
        super(TestNeutronNetworkActions, self).setUp()
        mgr_utils.mock_the_extension_manager(driver='fake')
        self.config(enabled_drivers=['fake'])
        self.node = object_utils.create_test_node(self.context)
        self.ports = [object_utils.create_test_port(
            self.context, node_id=self.node.id,
            uuid='1be26c0b-03f2-4d2e-ae87-c02d7f33c782',
            address='52:54:00:cf:2d:32',
            extra={'vif_port_id': uuidutils.generate_uuid()}
        )]
        # Very simple neutron port representation
        self.neutron_port = {'id': '132f871f-eaec-4fed-9475-0d54465e0f00',
                             'mac_address': '52:54:00:cf:2d:32'}
        self.network_uuid = uuidutils.generate_uuid()

    @mock.patch.object(client.Client, 'create_port')
    def test_add_ports_to_vlan_network(self, create_mock):
        port = self.ports[0]
        expected_body = {
            'port': {
                'network_id': self.network_uuid,
                'admin_state_up': True,
                'binding:vnic_type': 'baremetal',
                'device_owner': 'baremetal:none',
                'binding:host_id': self.node.uuid,
                'device_id': self.node.uuid,
                'mac_address': port.address,
                'binding:profile': {
                    'local_link_information': [port.local_link_connection]
                }
            }
        }
        # Ensure we can create ports
        create_mock.return_value = {'port': self.neutron_port}
        expected = {port.uuid: self.neutron_port['id']}
        old_vif_port_id = port.extra['vif_port_id']
        with task_manager.acquire(self.context, self.node.uuid) as task:
            ports = neutron.add_ports_to_network(task, self.network_uuid)
            port.refresh()
            self.assertEqual(expected, ports)
            create_mock.assert_called_once_with(expected_body)
            self.assertEqual(old_vif_port_id, port.extra['tenant_vif_port_id'])
            self.assertEqual(self.neutron_port['id'],
                             port.extra['vif_port_id'])

    @mock.patch.object(client.Client, 'create_port')
    def test_add_ports_to_flat_network(self, create_mock):
        port = self.ports[0]
        expected_body = {
            'port': {
                'network_id': self.network_uuid,
                'admin_state_up': True,
                'binding:vnic_type': 'baremetal',
                'device_owner': 'baremetal:none',
                'device_id': self.node.uuid,
                'mac_address': port.address,
                'binding:profile': {
                    'local_link_information': [port.local_link_connection]
                }
            }
        }
        # Ensure we can create ports
        create_mock.return_value = {'port': self.neutron_port}
        expected = {port.uuid: self.neutron_port['id']}
        old_vif_port_id = port.extra['vif_port_id']
        with task_manager.acquire(self.context, self.node.uuid) as task:
            ports = neutron.add_ports_to_network(task, self.network_uuid,
                                                 is_flat=True)
            port.refresh()
            self.assertEqual(expected, ports)
            create_mock.assert_called_once_with(expected_body)
            self.assertEqual(old_vif_port_id, port.extra['tenant_vif_port_id'])
            self.assertEqual(self.neutron_port['id'],
                             port.extra['vif_port_id'])

    @mock.patch.object(client.Client, 'create_port')
    def test_add_ports_to_vlan_network_no_vif_port_id(self, create_mock):
        port = self.ports[0]
        port.extra = {}
        port.save()
        expected_body = {
            'port': {
                'network_id': self.network_uuid,
                'admin_state_up': True,
                'binding:vnic_type': 'baremetal',
                'device_owner': 'baremetal:none',
                'binding:host_id': self.node.uuid,
                'device_id': self.node.uuid,
                'mac_address': port.address,
                'binding:profile': {
                    'local_link_information': [port.local_link_connection]
                }
            }
        }
        # Ensure we can create ports
        create_mock.return_value = {'port': self.neutron_port}
        expected = {port.uuid: self.neutron_port['id']}
        with task_manager.acquire(self.context, self.node.uuid) as task:
            ports = neutron.add_ports_to_network(task, self.network_uuid)
            port.refresh()
            self.assertEqual(expected, ports)
            create_mock.assert_called_once_with(expected_body)
            self.assertNotIn('tenant_vif_port_id', port.extra)
            self.assertEqual(self.neutron_port['id'],
                             port.extra['vif_port_id'])

    @mock.patch.object(client.Client, 'create_port')
    def test_add_ports_to_vlan_network_instance_uuid(self, create_mock):
        self.node.instance_uuid = uuidutils.generate_uuid()
        self.node.save()
        port = self.ports[0]
        expected_body = {
            'port': {
                'network_id': self.network_uuid,
                'admin_state_up': True,
                'binding:vnic_type': 'baremetal',
                'device_owner': 'baremetal:none',
                'binding:host_id': self.node.uuid,
                'device_id': self.node.instance_uuid,
                'mac_address': port.address,
                'binding:profile': {
                    'local_link_information': [port.local_link_connection]
                }
            }
        }
        # Ensure we can create ports
        create_mock.return_value = {'port': self.neutron_port}
        expected = {port.uuid: self.neutron_port['id']}
        old_vif_port_id = port.extra['vif_port_id']
        with task_manager.acquire(self.context, self.node.uuid) as task:
            ports = neutron.add_ports_to_network(task, self.network_uuid)
            port.refresh()
            self.assertEqual(expected, ports)
            create_mock.assert_called_once_with(expected_body)
            self.assertEqual(old_vif_port_id, port.extra['tenant_vif_port_id'])
            self.assertEqual(self.neutron_port['id'],
                             port.extra['vif_port_id'])

    @mock.patch.object(neutron, 'rollback_ports')
    @mock.patch.object(client.Client, 'create_port')
    def test_add_network_fail(self, create_mock, rollback_mock):
        # Check that if creating a port fails, the ports are cleaned up
        create_mock.side_effect = neutron_client_exc.ConnectionFailed

        with task_manager.acquire(self.context, self.node.uuid) as task:
            self.assertRaisesRegex(
                exception.NetworkError, 'Could not create port',
                neutron.add_ports_to_network, task, self.network_uuid)
            rollback_mock.assert_called_once_with(task, self.network_uuid)

    @mock.patch.object(neutron, 'rollback_ports')
    @mock.patch.object(client.Client, 'create_port', return_value={})
    def test_add_network_fail_create_any_port_empty(self, create_mock,
                                                    rollback_mock):
        with task_manager.acquire(self.context, self.node.uuid) as task:
            self.assertRaisesRegex(
                exception.NetworkError, 'any port',
                neutron.add_ports_to_network, task, self.network_uuid)
            self.assertFalse(rollback_mock.called)

    @mock.patch.object(neutron, 'LOG')
    @mock.patch.object(neutron, 'rollback_ports')
    @mock.patch.object(client.Client, 'create_port')
    def test_add_network_fail_create_some_ports_empty(self, create_mock,
                                                      rollback_mock, log_mock):
        port2 = object_utils.create_test_port(
            self.context, node_id=self.node.id,
            uuid=uuidutils.generate_uuid(),
            address='52:54:55:cf:2d:32',
            extra={'vif_port_id': uuidutils.generate_uuid()}
        )
        create_mock.side_effect = [{'port': self.neutron_port}, {}]
        with task_manager.acquire(self.context, self.node.uuid) as task:
            neutron.add_ports_to_network(task, self.network_uuid)
            self.assertIn(str(port2.uuid),
                          # Call #0, argument #1
                          log_mock.warning.call_args[0][1]['ports'])
            self.assertFalse(rollback_mock.called)

    @mock.patch.object(neutron, 'remove_neutron_ports')
    def test_remove_ports_from_network(self, remove_mock):
        with task_manager.acquire(self.context, self.node.uuid) as task:
            neutron.remove_ports_from_network(task, self.network_uuid)
            remove_mock.assert_called_once_with(
                {'network_id': self.network_uuid,
                 'mac_address': [self.ports[0].address]},
                self.node.uuid
            )

    @mock.patch.object(client.Client, 'delete_port')
    @mock.patch.object(client.Client, 'list_ports')
    def test_remove_neutron_ports(self, list_mock, delete_mock):
        list_mock.return_value = {'ports': [self.neutron_port]}
        neutron.remove_neutron_ports({'param': 'value'}, self.node.uuid)
        list_mock.assert_called_once_with(**{'param': 'value'})
        delete_mock.assert_called_once_with(self.neutron_port['id'])

    @mock.patch.object(client.Client, 'list_ports')
    def test_remove_neutron_ports_list_fail(self, list_mock):
        # Check that if listing ports fails, the node goes to cleanfail
        list_mock.side_effect = neutron_client_exc.ConnectionFailed
        self.assertRaises(exception.NetworkError,
                          neutron.remove_neutron_ports, {'param': 'value'},
                          self.node.uuid)
        list_mock.assert_called_once_with(**{'param': 'value'})

    @mock.patch.object(client.Client, 'delete_port')
    @mock.patch.object(client.Client, 'list_ports')
    def test_remove_neutron_ports_delete_fail(self, list_mock, delete_mock):
        # Check that if deleting ports fails, the node goes to cleanfail
        delete_mock.side_effect = neutron_client_exc.ConnectionFailed
        list_mock.return_value = {'ports': [self.neutron_port]}
        self.assertRaises(exception.NetworkError,
                          neutron.remove_neutron_ports, {'param': 'value'},
                          self.node.uuid)
        list_mock.assert_called_once_with(**{'param': 'value'})
        delete_mock.assert_called_once_with(self.neutron_port['id'])

    def test_get_node_portmap(self):
        with task_manager.acquire(self.context, self.node.uuid) as task:
            portmap = neutron.get_node_portmap(task)
            self.assertEqual(
                {self.ports[0].uuid: self.ports[0].local_link_connection},
                portmap
            )

    @mock.patch.object(neutron, 'remove_ports_from_network')
    def test_rollback_ports(self, remove_mock):
        with task_manager.acquire(self.context, self.node.uuid) as task:
            neutron.rollback_ports(task, self.network_uuid)
            remove_mock.assert_called_once_with(task, self.network_uuid)

    @mock.patch.object(neutron, 'LOG')
    @mock.patch.object(neutron, 'remove_ports_from_network')
    def test_rollback_ports_exception(self, remove_mock, log_mock):
        remove_mock.side_effect = Exception('boom')
        with task_manager.acquire(self.context, self.node.uuid) as task:
            neutron.rollback_ports(task, self.network_uuid)
            self.assertTrue(log_mock.exception.called)
