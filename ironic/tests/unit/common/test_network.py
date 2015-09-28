# Copyright 2014 Rackspace Inc.
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
import inspect
import mock
from neutronclient.common import exceptions as neutron_client_exc
from neutronclient.v2_0 import client
from oslo_config import cfg
from oslo_utils import uuidutils
import stevedore

from ironic.common import exception
from ironic.common import network
from ironic.conductor import task_manager
from ironic.networks import base as base_class
from ironic.networks import neutron_plugin as neutron
from ironic.networks import none
from ironic.tests import base
from ironic.tests.unit.conductor import mgr_utils
from ironic.tests.unit.db import base as db_base
from ironic.tests.unit.db import utils as db_utils
from ironic.tests.unit.objects import utils as object_utils


class TestNetwork(db_base.DbTestCase):

    def setUp(self):
        super(TestNetwork, self).setUp()
        mgr_utils.mock_the_extension_manager(driver='fake')
        self.config(enabled_drivers=['fake'])
        self.config(network_provider='neutron_plugin')
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

    def test_default_network_provider(self):
        # network provider should default to neutron
        with task_manager.acquire(self.context, self.node.uuid) as task:
            network_provider = task.node.network_provider
            net_provider = network.get_network_provider(network_provider)
            self.assertIsInstance(net_provider,
                                  neutron.NeutronV2NetworkProvider)

    def test_set_bad_network_provider(self):
        self.config(network_provider='bad_network_plugin')

        with task_manager.acquire(self.context, self.node.uuid) as task:
            network_provider = task.node.network_provider
            self.assertRaises(exception.NetworkProviderNotFound,
                              network.get_network_provider, network_provider)

    @mock.patch.object(stevedore.driver, 'DriverManager', autospec=True)
    def test_network_provider_some_error(self, mock_drv_mgr):
        mock_drv_mgr.side_effect = exception.NetworkProviderNotFound(
            'No module mymod found.')

        with task_manager.acquire(self.context, self.node.uuid) as task:
            network_provider = task.node.network_provider
            self.assertRaises(exception.NetworkProviderNotFound,
                              network.get_network_provider, network_provider)

    def test_set_none_network_provider(self):
        self.config(network_provider='none')

        with task_manager.acquire(self.context, self.node.uuid) as task:
            network_provider = task.node.network_provider
            net_provider = network.get_network_provider(network_provider)
            self.assertIsInstance(net_provider, none.NoopNetworkProvider)

    def test_set_neutron_network_provider(self):
        self.config(network_provider='neutron_plugin')

        with task_manager.acquire(self.context, self.node.uuid) as task:
            network_provider = task.node.network_provider
            net_provider = network.get_network_provider(network_provider)
            self.assertIsInstance(net_provider,
                                  neutron.NeutronV2NetworkProvider)

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
        network.get_neutron_client(token=token)
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
        network.get_neutron_client(token=None)
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
        network.get_neutron_client(token=None)
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
        network.get_neutron_client(token=None)
        mock_client_init.assert_called_once_with(**expected)

    def test_out_range_auth_strategy(self):
        self.assertRaises(ValueError, cfg.CONF.set_override,
                          'auth_strategy', 'fake', 'neutron',
                          enforce_type=True)

    def test_get_node_vif_ids_no_ports(self):
        expected = {'portgroups': {},
                    'ports': {}}
        with task_manager.acquire(self.context, self.node.uuid) as task:
            result = network.get_node_vif_ids(task)
        self.assertEqual(expected, result)

    def test_get_node_vif_ids_no_ports_no_portgroups(self):
        expected = {'portgroups': {},
                    'ports': {}}
        with task_manager.acquire(self.context, self.node.uuid) as task:
            result = network.get_node_vif_ids(task)
        self.assertEqual(expected, result)

    def test_get_node_vif_ids_one_port(self):
        port1 = db_utils.create_test_port(node_id=self.node.id,
                                          address='aa:bb:cc:dd:ee:ff',
                                          uuid=uuidutils.generate_uuid(),
                                          extra={'vif_port_id': 'test-vif-A'},
                                          driver='fake')
        expected = {'portgroups': {},
                    'ports': {port1.uuid: 'test-vif-A'}}
        with task_manager.acquire(self.context, self.node.uuid) as task:
            result = network.get_node_vif_ids(task)
        self.assertEqual(expected, result)

    def test_get_node_vif_ids_one_portgroup(self):
        pg1 = db_utils.create_test_portgroup(
            node_id=self.node.id,
            extra={'vif_port_id': 'test-vif-A'})

        expected = {'portgroups': {pg1.uuid: 'test-vif-A'},
                    'ports': {}}
        with task_manager.acquire(self.context, self.node.uuid) as task:
            result = network.get_node_vif_ids(task)
        self.assertEqual(expected, result)

    def test_get_node_vif_ids_two_ports(self):
        port1 = db_utils.create_test_port(node_id=self.node.id,
                                          address='aa:bb:cc:dd:ee:ff',
                                          uuid=uuidutils.generate_uuid(),
                                          extra={'vif_port_id': 'test-vif-A'},
                                          driver='fake')
        port2 = db_utils.create_test_port(node_id=self.node.id,
                                          address='dd:ee:ff:aa:bb:cc',
                                          uuid=uuidutils.generate_uuid(),
                                          extra={'vif_port_id': 'test-vif-B'},
                                          driver='fake')
        expected = {'portgroups': {},
                    'ports': {port1.uuid: 'test-vif-A',
                              port2.uuid: 'test-vif-B'}}
        with task_manager.acquire(self.context, self.node.uuid) as task:
            result = network.get_node_vif_ids(task)
        self.assertEqual(expected, result)

    def test_get_node_vif_ids_two_portgroups(self):
        pg1 = db_utils.create_test_portgroup(
            node_id=self.node.id,
            extra={'vif_port_id': 'test-vif-A'})
        pg2 = db_utils.create_test_portgroup(
            uuid=uuidutils.generate_uuid(),
            address='dd:ee:ff:aa:bb:cc',
            node_id=self.node.id,
            name='barname',
            extra={'vif_port_id': 'test-vif-B'})
        expected = {'portgroups': {pg1.uuid: 'test-vif-A',
                                   pg2.uuid: 'test-vif-B'},
                    'ports': {}}
        with task_manager.acquire(self.context, self.node.uuid) as task:
            result = network.get_node_vif_ids(task)
        self.assertEqual(expected, result)

    @mock.patch.object(client.Client, 'delete_port')
    @mock.patch.object(client.Client, 'list_ports')
    def test_remove_ports_from_network(self, list_mock, delete_mock):
        # Ensure that we can delete cleaning ports, and that ports with
        # different macs don't get deleted
        other_port = {'id': '132f871f-eaec-4fed-9475-0d54465e0f01',
                      'mac_address': 'aa:bb:cc:dd:ee:ff'}
        with task_manager.acquire(self.context, self.node.uuid) as task:
            list_mock.return_value = {'ports': [self.neutron_port, other_port]}
            network.remove_ports_from_network(
                task, '00000000-0000-0000-0000-000000000000')
            list_mock.assert_called_once_with(
                network_id='00000000-0000-0000-0000-000000000000')
            delete_mock.assert_called_once_with(self.neutron_port['id'])

    @mock.patch.object(client.Client, 'list_ports')
    def test_remove_ports_from_network_list_fail(self, list_mock):
        # Check that if listing ports fails, the node goes to cleanfail
        list_mock.side_effect = neutron_client_exc.ConnectionFailed

        with task_manager.acquire(self.context, self.node.uuid) as task:
            self.assertRaises(exception.NetworkError,
                              network.remove_ports_from_network, task,
                              '00000000-0000-0000-0000-000000000000')
            list_mock.assert_called_once_with(
                network_id='00000000-0000-0000-0000-000000000000')

    @mock.patch.object(client.Client, 'delete_port')
    @mock.patch.object(client.Client, 'list_ports')
    def test_remove_ports_from_network_delete_fail(self, list_mock,
                                                   delete_mock):
        # Check that if deleting ports fails, the node goes to cleanfail
        delete_mock.side_effect = neutron_client_exc.ConnectionFailed
        with task_manager.acquire(self.context, self.node.uuid) as task:
            list_mock.return_value = {'ports': [self.neutron_port]}
            self.assertRaises(exception.NetworkError,
                              network.remove_ports_from_network, task,
                              '00000000-0000-0000-0000-000000000000')
            list_mock.assert_called_once_with(
                network_id='00000000-0000-0000-0000-000000000000')
            delete_mock.assert_called_once_with(self.neutron_port['id'])

    @mock.patch.object(client.Client, 'create_port')
    def test_add_ports_to_network(self, create_mock):
        # Ensure we can create ports
        create_mock.return_value = {'port': self.neutron_port}
        expected = {self.ports[0].uuid: self.neutron_port['id']}

        with task_manager.acquire(self.context, self.node.uuid) as task:
            task.node = self.node
            ports = network.add_ports_to_network(
                task, '00000000-0000-0000-0000-000000000000')
            self.assertEqual(expected, ports)

    @mock.patch('ironic.common.network.rollback_ports')
    @mock.patch.object(client.Client, 'create_port')
    def test_add_network_fail(self, create_mock, rollback_mock):
        # Check that if creating a port fails, the ports are cleaned up
        create_mock.side_effect = neutron_client_exc.ConnectionFailed

        with task_manager.acquire(self.context, self.node.uuid) as task:
            task.node = self.node
            self.assertRaises(
                exception.NetworkError, network.add_ports_to_network, task,
                '00000000-0000-0000-0000-000000000000')
            rollback_mock.assert_called_once_with(
                task,
                '00000000-0000-0000-0000-000000000000')


class CompareBasetoModules(base.TestCase):

    def test_drivers_match_network_provider_base(self):
        def _get_public_apis(inst):
            methods = {}
            for (name, value) in inspect.getmembers(inst, inspect.ismethod):
                if name.startswith("_"):
                    continue
                methods[name] = value
            return methods

        def _compare_classes(baseclass, driverclass):

            basemethods = _get_public_apis(baseclass)
            implmethods = _get_public_apis(driverclass)

            for name in basemethods:
                baseargs = inspect.getargspec(basemethods[name])
                implargs = inspect.getargspec(implmethods[name])
                self.assertEqual(
                    baseargs,
                    implargs,
                    "%s args of %s don't match base %s" % (
                        name,
                        driverclass,
                        baseclass)
                )

        _compare_classes(base_class.NetworkProvider,
                         none.NoopNetworkProvider)
        _compare_classes(base_class.NetworkProvider,
                         neutron.NeutronV2NetworkProvider)
