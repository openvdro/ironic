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

from ironic.common import exception
from ironic.common import neutron
from ironic.conductor import task_manager
from ironic.tests.unit.conductor import mgr_utils
from ironic.tests.unit.db import base as db_base
from ironic.tests.unit.objects import utils as object_utils


class TestNetwork(db_base.DbTestCase):

    def setUp(self):
        super(TestNetwork, self).setUp()
        mgr_utils.mock_the_extension_manager(driver='fake')
        self.config(enabled_drivers=['fake'])
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
        self.node = object_utils.create_test_node(self.context)
        self.ports = [
            object_utils.create_test_port(
                self.context, node_id=self.node.id, id=2,
                uuid='1be26c0b-03f2-4d2e-ae87-c02d7f33c782',
                address='52:54:00:cf:2d:32')]
        # Very simple neutron port representation
        self.neutron_port = {'id': '132f871f-eaec-4fed-9475-0d54465e0f00',
                             'mac_address': '52:54:00:cf:2d:32'}

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

    @mock.patch.object(client.Client, 'delete_port')
    @mock.patch.object(client.Client, 'list_ports')
    def test_remove_ports_from_network(self, list_mock, delete_mock):
        # Ensure that we can delete cleaning ports, and that ports with
        # different macs don't get deleted
        other_port = {'id': '132f871f-eaec-4fed-9475-0d54465e0f01',
                      'mac_address': 'aa:bb:cc:dd:ee:ff'}
        with task_manager.acquire(self.context, self.node.uuid) as task:
            list_mock.return_value = {'ports': [self.neutron_port, other_port]}
            neutron.remove_ports_from_network(
                task, '00000000-0000-0000-0000-000000000000')
            list_mock.assert_called_once_with(
                **{'network_id': '00000000-0000-0000-0000-000000000000'})
            delete_mock.assert_called_once_with(self.neutron_port['id'])

    @mock.patch.object(client.Client, 'list_ports')
    def test_remove_ports_from_network_list_fail(self, list_mock):
        # Check that if listing ports fails, the node goes to cleanfail
        list_mock.side_effect = neutron_client_exc.ConnectionFailed

        with task_manager.acquire(self.context, self.node.uuid) as task:
            self.assertRaises(exception.NetworkError,
                              neutron.remove_ports_from_network, task,
                              '00000000-0000-0000-0000-000000000000')
            list_mock.assert_called_once_with(
                **{'network_id': '00000000-0000-0000-0000-000000000000'})

    @mock.patch.object(client.Client, 'delete_port')
    @mock.patch.object(client.Client, 'list_ports')
    def test_remove_ports_from_network_delete_fail(self, list_mock,
                                                   delete_mock):
        # Check that if deleting ports fails, the node goes to cleanfail
        delete_mock.side_effect = neutron_client_exc.ConnectionFailed
        with task_manager.acquire(self.context, self.node.uuid) as task:
            list_mock.return_value = {'ports': [self.neutron_port]}
            self.assertRaises(exception.NetworkError,
                              neutron.remove_ports_from_network, task,
                              '00000000-0000-0000-0000-000000000000')
            list_mock.assert_called_once_with(
                **{'network_id': '00000000-0000-0000-0000-000000000000'})
            delete_mock.assert_called_once_with(self.neutron_port['id'])

    @mock.patch.object(client.Client, 'create_port')
    def test_add_ports_to_network(self, create_mock):
        # Ensure we can create ports
        create_mock.return_value = {'port': self.neutron_port}
        expected = {self.ports[0].uuid: self.neutron_port['id']}

        with task_manager.acquire(self.context, self.node.uuid) as task:
            task.node = self.node
            ports = neutron.add_ports_to_network(
                task, '00000000-0000-0000-0000-000000000000')
            self.assertEqual(expected, ports)

    @mock.patch('ironic.common.neutron.rollback_ports')
    @mock.patch.object(client.Client, 'create_port')
    def test_add_network_fail(self, create_mock, rollback_mock):
        # Check that if creating a port fails, the ports are cleaned up
        create_mock.side_effect = neutron_client_exc.ConnectionFailed

        with task_manager.acquire(self.context, self.node.uuid) as task:
            task.node = self.node
            self.assertRaises(
                exception.NetworkError, neutron.add_ports_to_network, task,
                '00000000-0000-0000-0000-000000000000')
            rollback_mock.assert_called_once_with(
                task,
                '00000000-0000-0000-0000-000000000000')
